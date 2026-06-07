// AETHER x86_64 boot pipeline
//
// Mirrors arm64_entry::efi_main but with x86_64 privilege semantics:
//
//   1. UEFI calls efi_main (ring 0, long mode, paging on, NOT yet in
//      VMX root / SVM host mode).
//   2. We capture CPU vendor via CPUID leaf 0.
//   3. We capture the ACPI RSDP from the EFI config table.
//   4. ExitBootServices (BootContext::run — same as ARM path).
//   5. ConOut is gone. Switch to direct COM1 serial output (0x3F8).
//   6. Build a minimal EPT (Intel) or NPT (AMD) identity map covering
//      the static `GUEST_RAM` 2 MiB region.
//   7. Place a guest payload (single `hlt` instruction) at guest RAM
//      offset 0.
//   8. Branch on vendor:
//        Intel -> init_vtx_foundation -> VMLAUNCH
//        AMD   -> init_svm_foundation -> VMRUN
//   9. First VMEXIT (HLT) is observed at the host VMEXIT handler
//      (Intel) or at the instruction after VMRUN (AMD); we print the
//      exit reason via COM1 and halt.
//
// Gate: serial output reads "[x86] vmexit reason=0x0C" (HLT_EXIT for
// Intel, exit_code 0x78 for AMD).

#![cfg(target_arch = "x86_64")]

use core::ffi::c_void;
use core::ptr;

// ─────────────────────────────────────────────────────────────────────────────
// GOP framebuffer info — captured BEFORE ExitBootServices (passed in from
// main.rs x86_entry via set_framebuffer).  Used post-EBS to paint the screen
// as a visible success/fail indicator on machines without serial ports.
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
pub struct FramebufferInfo {
    pub base:        u64,
    pub size:        u64,
    pub width:       u32,
    pub height:      u32,
    pub pitch_px:    u32, // pixels-per-scan-line
    pub bgr_format:  bool, // true = BGRA8 (most common), false = RGBA8
}

static mut FB_INFO: Option<FramebufferInfo> = None;

pub fn set_framebuffer(fb: FramebufferInfo) {
    unsafe { FB_INFO = Some(fb); }
}

/// Fill the entire visible framebuffer with a solid colour.  Safe to call
/// after ExitBootServices because the GOP framebuffer PA is identity-mapped
/// by UEFI and stays mapped until we replace CR3 (which we do not).
///
/// NOTE: Diagnostic colour-fill removed — VGA text mode + COM1 serial are now
/// the sole diagnostic surface. Kept here for future framebuffer painters.
#[allow(dead_code)]
unsafe fn fb_fill(rgb: u32) {
    unsafe {
        let fb = match FB_INFO {
            Some(f) => f,
            None    => return,
        };
        let pixel: u32 = if fb.bgr_format {
            // Convert RGB -> BGR: swap R and B bytes.
            ((rgb & 0x0000FF) << 16) | (rgb & 0x00FF00) | ((rgb & 0xFF0000) >> 16)
        } else {
            rgb
        };
        let base = fb.base as *mut u32;
        for y in 0..fb.height {
            for x in 0..fb.width {
                *base.add((y * fb.pitch_px + x) as usize) = pixel;
            }
        }
    }
}

// Real-hardware verification (May 2026 Ryzen boot test) showed the GOP
// framebuffer on a modern AMD board displays RED and BLUE swapped vs what
// the bgr_format detection in capture_framebuffer assumes. GREEN/AMBER/
// PURPLE are invariant under R/B swap. Keep the human-readable name on the
// LHS and put the byte-pattern that paints the EXPECTED COLOR on the RHS:
//
//   FB_RED  paints red  on this hardware (was 0xFF0000 → showed as blue)
//   FB_BLUE paints blue on this hardware (was 0x0000FF → showed as red)
// FB_RED is the only color still actively used (halt()). The others are
// kept in the file as documented constants for future diagnostic helpers
// that don't wipe the screen — fb_fill() is destructive to dual_puts text.
#[allow(dead_code)] const FB_GREEN:  u32 = 0x00_00FF00;
                    const FB_RED:    u32 = 0x00_0000FF; // hardware-corrected (was 0xFF0000)
#[allow(dead_code)] const FB_AMBER:  u32 = 0x00_FFAA00;
#[allow(dead_code)] const FB_BLUE:   u32 = 0x00_FF0000; // hardware-corrected (was 0x0000FF)
#[allow(dead_code)] const FB_PURPLE: u32 = 0x00_8000FF;

// ─────────────────────────────────────────────────────────────────────────────
// Visual + audible diagnostics post-ExitBootServices.
//
// On a modern UEFI-only AMD board with no serial cable, our dual_puts(...)
// output (VGA text mode 0xB8000 + COM1 0x3F8) is invisible — there is no
// legacy VGA text framebuffer and there is no physical serial port.
//
// These checkpoints give the user observable feedback through the GOP
// framebuffer (captured pre-EBS) and the PC speaker (PIT channel 2 + port
// 0x61, hardware-only, no firmware deps):
//
//   GREEN flash + 1 beep   = ExitBootServices returned OK
//   BLUE  flash + 2 beeps  = about to enter the guest (VMLAUNCH/VMRUN)
//   AMBER flash            = VMEXIT handler ran (we're servicing the guest)
//   RED   flash + 3 beeps  = halt() reached (fatal — fix and reboot)
//
// All four work without UEFI services and without a serial cable.
// ─────────────────────────────────────────────────────────────────────────────

// Busy-wait iteration counts for the PC-speaker diagnostics. Calibrated for
// ~3 GHz silicon (≈150 ms hold). Under QEMU TCG these take tens of seconds
// each, stalling the dev boot loop, so the `qemu` feature collapses them to a
// negligible spin (the port I/O still happens — only the audible hold shrinks).
#[cfg(not(feature = "qemu"))]
const BEEP_HOLD_ITERS: u32 = 200_000_000;
#[cfg(feature = "qemu")]
const BEEP_HOLD_ITERS: u32 = 20_000;
#[cfg(not(feature = "qemu"))]
const BEEP_GAP_ITERS: u32 = 40_000_000;
#[cfg(feature = "qemu")]
const BEEP_GAP_ITERS: u32 = 4_000;
#[cfg(not(feature = "qemu"))]
const BISECT_SILENCE_ITERS: u32 = 600_000_000;
#[cfg(feature = "qemu")]
const BISECT_SILENCE_ITERS: u32 = 60_000;

/// PC speaker beep — PIT channel 2 drives the speaker at the given frequency
/// for ~150 ms. The 1.193182 MHz PIT clock divides down to `freq` Hz.
/// Implementation: SDM-equivalent port I/O sequence used since the IBM PC.
#[inline]
unsafe fn beep_once(freq_hz: u32) {
    unsafe {
        let divisor: u16 = (1_193_182u32 / freq_hz.max(1)).min(0xFFFF) as u16;
        // Program PIT channel 2: mode 3 (square wave), access lobyte then hibyte.
        outb(0x43, 0xB6);
        outb(0x42, (divisor & 0xFF) as u8);
        outb(0x42, ((divisor >> 8) & 0xFF) as u8);
        // Enable speaker (port 0x61 bits 0 and 1).
        let prev = inb(0x61);
        outb(0x61, prev | 0x03);
        // Hold for ~150 ms — busy loop. We don't have time services here.
        // Calibrated against a ~3 GHz core; doesn't need to be exact.
        for _ in 0..BEEP_HOLD_ITERS {
            core::arch::asm!("pause", options(nomem, nostack));
        }
        outb(0x61, prev & !0x03);
    }
}

#[inline]
unsafe fn beep_n(n: u32, freq_hz: u32) {
    unsafe {
        for _ in 0..n {
            beep_once(freq_hz);
            // Gap between beeps so they're distinguishable.
            for _ in 0..BEEP_GAP_ITERS {
                core::arch::asm!("pause", options(nomem, nostack));
            }
        }
    }
}

/// One-shot status indicator: paint the framebuffer + beep.
unsafe fn checkpoint(color: u32, beeps: u32, freq_hz: u32) {
    unsafe {
        fb_fill(color);
        beep_n(beeps, freq_hz);
    }
}

/// Bisection marker — emit a distinct PITCH for each step the hypervisor
/// reaches. The user identifies the LAST clearly-audible pitch to know
/// which step it reached. Followed by a ~1-second clear silence so each
/// group is unambiguous.
///
/// Pitch ladder (rising — higher pitch = deeper in boot):
///   step 2  -> 500 Hz   (low-medium)   past post-EBS PA-print block
///   step 3  -> 600 Hz                  past prepare_android_handoff
///   step 4  -> 700 Hz                  past try_init_fex
///   step 5  -> 800 Hz                  inside boot_amd, past NPT identity
///   step 6  -> 900 Hz                  past build_npt_2mib_range (1-GiB)
///   step 7  -> 1000 Hz                 past build_guest_page_table
///   step 8  -> 1200 Hz                 past init_svm_foundation
///   step 9  -> 1500 Hz  (highest)      past translator_dbt_init
///   then BLUE + 2 beeps @ 1100 Hz = entering VMRUN loop.
#[allow(dead_code)]
unsafe fn bisect(step: u32) {
    let freq = match step {
        2 => 500,
        3 => 600,
        4 => 700,
        5 => 800,
        6 => 900,
        7 => 1000,
        8 => 1200,
        9 => 1500,
        _ => 660,
    };
    unsafe {
        // Single ~150 ms beep at the step's distinct pitch.
        beep_once(freq);
        // ~1 second of clear silence so this group is unambiguously
        // separated from the next bisect/checkpoint.
        for _ in 0..BISECT_SILENCE_ITERS {
            core::arch::asm!("pause", options(nomem, nostack));
        }
    }
}

use crate::android_handoff::{
    prepare_android_handoff_at, AndroidHandoff, HandoffError,
};
use crate::boot::{BootContext, EfiSystemTable};
#[cfg(feature = "fex_linked")]
use crate::dbt_integration::{
    init_dbt_integration_hv, AotPreTranslationQueue, HvDbtError, DbtHostBindings, DbtIntegrationConfig,
    DbtJitCache,
};
use crate::svm::{
    init_svm_foundation, set_active_npt, vmrun, NptTable, NptTableEntry,
    SvmFoundationConfig, VmcbRegion, VMCB_SAVE_CR3,
    VMCB_EXIT_INFO_1, VMCB_EXIT_INFO_2,
};
use crate::vtx::{
    init_vtx_foundation, set_active_ept, vmread, vmwrite, EptTable, EptTableEntry,
    Eptp, VmcsRegion, VmxonRegion, VtxFoundationConfig, VMCS_GUEST_CR3,
};
use crate::dbt_integration::install_dbt_ept_callbacks;
use aether_translator::dbt::{
    aether_dbt_init as translator_dbt_init, JIT_CACHE_BYTES as TRANSLATOR_JIT_BYTES,
    aether_dbt_block_host_va, aether_dbt_last_failure, aether_dbt_translate_block,
    block_bytes_are_safe, AetherDbtResult,
};
use aether_translator::runtime::GuestRegisterFile;
use crate::x86_hw_validation::CpuVendor;

// Compile-time guard: the flat M2_REGFILE static below is sized to match the
// translator's GuestRegisterFile (which translated blocks address via [R15+disp]).
// If the struct ever changes size, fail the build instead of silently corrupting
// the register file at runtime.
const _: () = assert!(core::mem::size_of::<GuestRegisterFile>() == 0x328);

// ─────────────────────────────────────────────────────────────────────────────
// COM1 serial (0x3F8) — post-ExitBootServices debug output.
// 16550 UART register layout (legacy PC).
// ─────────────────────────────────────────────────────────────────────────────

const COM1_BASE: u16 = 0x3F8;
const COM1_THR:  u16 = COM1_BASE + 0; // Transmit Holding Register
const COM1_DLL:  u16 = COM1_BASE + 0; // Divisor Latch Low (when DLAB=1)
const COM1_DLM:  u16 = COM1_BASE + 1; // Divisor Latch High (when DLAB=1)
const COM1_IER:  u16 = COM1_BASE + 1; // Interrupt Enable Register
const COM1_FCR:  u16 = COM1_BASE + 2; // FIFO Control Register
const COM1_LCR:  u16 = COM1_BASE + 3; // Line Control Register
const COM1_MCR:  u16 = COM1_BASE + 4; // Modem Control Register
const COM1_LSR:  u16 = COM1_BASE + 5; // Line Status Register

#[inline]
unsafe fn outb(port: u16, value: u8) {
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") port,
            in("al") value,
            options(nomem, nostack, preserves_flags),
        );
    }
}

#[inline]
unsafe fn inb(port: u16) -> u8 {
    let v: u8;
    unsafe {
        core::arch::asm!(
            "in al, dx",
            in("dx") port,
            out("al") v,
            options(nomem, nostack, preserves_flags),
        );
    }
    v
}

/// Initialize COM1 for 115200 8N1 polled TX. Safe to call after
/// ExitBootServices: no UEFI dependencies.
pub unsafe fn com1_init() {
    unsafe {
        outb(COM1_IER, 0x00);            // disable interrupts
        outb(COM1_LCR, 0x80);            // enable DLAB
        outb(COM1_DLL, 0x01);            // divisor low  = 1  (115200 baud)
        outb(COM1_DLM, 0x00);            // divisor high = 0
        outb(COM1_LCR, 0x03);            // 8N1, DLAB cleared
        outb(COM1_FCR, 0xC7);            // enable + clear FIFOs, 14-byte threshold
        outb(COM1_MCR, 0x0B);            // DTR + RTS + OUT2
    }
}

/// Poll-wait until the Transmit Holding Register is empty, then write byte.
#[inline]
unsafe fn com1_putb(b: u8) {
    unsafe {
        // LSR bit 5 (THRE) = Transmit Holding Register Empty.
        while inb(COM1_LSR) & 0x20 == 0 {
            core::hint::spin_loop();
        }
        outb(COM1_THR, b);
    }
}

pub unsafe fn com1_puts(s: &[u8]) {
    for &b in s {
        if b == b'\n' {
            unsafe { com1_putb(b'\r'); }
        }
        unsafe { com1_putb(b); }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VGA text mode (0xB8000) — visible diagnostics for machines without a serial
// port.  On UEFI, the firmware may have switched the GPU into framebuffer
// mode where 0xB8000 is no longer the active display surface.  In that case
// these writes are harmless but invisible.  On any machine with CSM/legacy
// support, OR any machine that left the GPU in text mode, the messages
// appear on-screen.
//
// Layout: 80 columns x 25 rows, two bytes per cell (char + attribute byte).
// Attribute 0x07 = light-gray on black.  Attribute 0x0F = bright white.
// ─────────────────────────────────────────────────────────────────────────────

const VGA_BUF:   u64   = 0xB8000;
const VGA_COLS:  usize = 80;
const VGA_ROWS:  usize = 25;
const VGA_ATTR:  u8    = 0x0F; // bright white on black

static mut VGA_ROW: usize = 0;
static mut VGA_COL: usize = 0;

unsafe fn vga_putc(b: u8) {
    unsafe {
        if b == b'\n' || VGA_COL >= VGA_COLS {
            VGA_COL = 0;
            VGA_ROW += 1;
            if VGA_ROW >= VGA_ROWS {
                // Scroll: copy rows 1..ROWS up by one row.
                let buf = VGA_BUF as *mut u16;
                for row in 1..VGA_ROWS {
                    for col in 0..VGA_COLS {
                        let src = *buf.add(row * VGA_COLS + col);
                        *buf.add((row - 1) * VGA_COLS + col) = src;
                    }
                }
                // Clear the bottom row.
                for col in 0..VGA_COLS {
                    *buf.add((VGA_ROWS - 1) * VGA_COLS + col) = 0x0F20; // space, bright white
                }
                VGA_ROW = VGA_ROWS - 1;
            }
            if b == b'\n' { return; }
        }
        let off = VGA_ROW * VGA_COLS + VGA_COL;
        let cell: u16 = (b as u16) | ((VGA_ATTR as u16) << 8);
        *(VGA_BUF as *mut u16).add(off) = cell;
        VGA_COL += 1;
    }
}

pub unsafe fn vga_clear() {
    unsafe {
        let buf = VGA_BUF as *mut u16;
        let blank: u16 = 0x0F20; // space char with bright-white attribute
        for i in 0..(VGA_COLS * VGA_ROWS) {
            *buf.add(i) = blank;
        }
        VGA_ROW = 0;
        VGA_COL = 0;
    }
}

pub unsafe fn vga_puts(s: &[u8]) {
    for &b in s {
        unsafe { vga_putc(b); }
    }
}

pub unsafe fn vga_puthex64(v: u64) {
    unsafe { vga_puts(b"0x"); }
    let mut buf = [0u8; 16];
    for i in 0..16 {
        let nib = ((v >> (60 - i * 4)) & 0xF) as u8;
        buf[i] = if nib < 10 { b'0' + nib } else { b'a' + nib - 10 };
    }
    unsafe { vga_puts(&buf); }
}

/// Print to both COM1 (serial) and VGA text mode.
pub unsafe fn dual_puts(s: &[u8]) {
    unsafe { com1_puts(s); vga_puts(s); fb_text_puts(s); }
}

pub unsafe fn dual_puthex64(v: u64) {
    unsafe { com1_puthex64(v); vga_puthex64(v); fb_text_puthex64(v); }
}

// ─────────────────────────────────────────────────────────────────────────────
// GOP framebuffer text painter — the third leg of dual_puts.
//
// On a modern UEFI-only AMD board with no serial cable and no legacy VGA
// text mode (writes to 0xB8000 go to unmapped memory), neither com1_puts
// nor vga_puts produces visible output. The GOP framebuffer captured
// pre-EBS is the only post-EBS surface that actually works.
//
// fb_text_puts wraps `setup_wizard::FramebufferPainter::draw_glyph` with a
// scrolling cursor. State:
//
//   FB_TEXT_X, FB_TEXT_Y   — cursor position in pixels (top-left of next
//                            8×8 glyph)
//   FB_TEXT_INIT           — whether fb_text_clear() has run (first call
//                            clears the FB and sets pixel order)
//
// On `\n`, cursor advances one row. On line overflow, cursor wraps to
// column 0 and advances. On row overflow, the framebuffer scrolls up by
// one row (8 px) — this keeps the latest output always visible at the
// bottom rather than wrapping back to the top, which would interleave
// new and stale text.
//
// All operations are no-ops if FB_INFO is None or if drawing is disabled
// via the kill switch (set on framebuffer-driver assignment, never used
// in current code path).
// ─────────────────────────────────────────────────────────────────────────────

use crate::setup_wizard::{FramebufferPainter, PixelOrder, FONT_8X8_FIRST_CHAR};

static mut FB_TEXT_X:    u32  = 0;
static mut FB_TEXT_Y:    u32  = 0;
static mut FB_TEXT_INIT: bool = false;

// Stashed pre-EBS ESP read result. We can't dual_puts pre-EBS because the
// framebuffer text painter is bound to the captured GOP framebuffer which
// only becomes our exclusive surface AFTER ExitBootServices. So we save
// the ESP error here and print it post-EBS in the normal boot log flow.
static mut STAGED_ESP_READ_BYTES: usize = 0;
static mut STAGED_ESP_ERR_KIND:   u8    = 0;
static mut STAGED_ESP_ERR_STATUS: usize = 0;
/// PA returned by `try_read_boot_img_alloc` for the UEFI-allocated staging
/// window, or 0 if allocation failed and the caller should fall back to
/// the legacy `STAGED_BOOT_IMG_PA` constant.
static mut STAGED_ALLOC_PA:       u64   = 0;

/// Base + size of the contiguous host-PA span the live dispatch loop treats as
/// the guest RAM window — the software-MMU clamp, `read_guest_window_identity`,
/// and the boot-path window pin all derive from this. Set from the prepared
/// handoff's `region_pa`/`region_size` (== the EPT/NPT `extra_region`) at arm
/// time. **Must NOT be the hardcoded `STAGED_BOOT_IMG_PA` constant**: when the
/// UEFI `AllocatePages` reader succeeds (the §2a path, used because 0x8000_0000
/// is not guaranteed conventional RAM on real boards) the kernel/DTB live at
/// `STAGED_ALLOC_PA` near 4 GiB, so a constant window rejects the very first
/// fetch and halts the loop before any guest instruction runs. 0 = unset →
/// fall back to the legacy constants (synthetic / pre-staged-at-0x8000_0000).
static mut DISPATCH_WINDOW_BASE:  u64   = 0;
static mut DISPATCH_WINDOW_SIZE:  u64   = 0;

// Light gray on dark navy — matches the wizard's WIZ_COLOR_FG / WIZ_COLOR_BG
// constants so the boot log visually flows into the wizard screens.
const FB_TEXT_FG: u32 = 0x00_E0E0E0;
const FB_TEXT_BG: u32 = 0x00_0E1117;

/// Borrow the captured GOP framebuffer as a FramebufferPainter. Returns
/// None if no framebuffer was captured (legacy BIOS / SimpleText-only
/// firmware). Caller must ensure no other code is concurrently painting
/// — this hypervisor is single-threaded post-EBS so that holds trivially.
unsafe fn fb_painter() -> Option<FramebufferPainter<'static>> {
    let fb = unsafe { FB_INFO? };
    if fb.base == 0 || fb.width == 0 || fb.height == 0 || fb.pitch_px == 0 {
        return None;
    }
    // The pre-EBS bgr_format flag was unreliable on the May 2026 Ryzen
    // test board, so the call sites that paint solid color rectangles
    // (checkpoint / fb_fill) work around it by swapping FB_RED/FB_BLUE
    // constants directly. For text we accept the flag at face value;
    // worst case the foreground appears in a different but legible
    // color (gray ↔ gray-ish), which is fine for diagnostic output.
    let order = if fb.bgr_format { PixelOrder::Bgr } else { PixelOrder::Rgb };
    let len_px = (fb.pitch_px as usize) * (fb.height as usize);
    let slice  = unsafe {
        core::slice::from_raw_parts_mut(fb.base as *mut u32, len_px)
    };
    Some(FramebufferPainter::new(slice, fb.width, fb.height, fb.pitch_px, order))
}

/// Clear the framebuffer to the boot-log background color and reset the
/// text cursor. Called lazily on first fb_text_puts.
unsafe fn fb_text_clear() {
    if let Some(mut p) = unsafe { fb_painter() } {
        p.clear(FB_TEXT_BG);
    }
    unsafe {
        FB_TEXT_X = 0;
        FB_TEXT_Y = 0;
        FB_TEXT_INIT = true;
    }
}

/// Scroll the entire framebuffer up by one 8-pixel row, clearing the
/// bottom row to the background. Called when the cursor would advance
/// past the last visible row.
unsafe fn fb_text_scroll_one_row() {
    let fb = match unsafe { FB_INFO } {
        Some(f) => f,
        None    => return,
    };
    if fb.base == 0 || fb.height < 8 || fb.pitch_px == 0 {
        return;
    }
    let pitch_bytes = (fb.pitch_px as usize) * 4;
    let row_bytes   = 8 * pitch_bytes;
    let total_bytes = (fb.height as usize) * pitch_bytes;
    if row_bytes >= total_bytes {
        return;
    }
    unsafe {
        let base = fb.base as *mut u8;
        // memmove: src = base + row_bytes, dst = base, len = total - row_bytes.
        // Source and dest overlap (forward shift); copy lowest-to-highest is
        // wrong direction. Use core::ptr::copy which handles overlap.
        core::ptr::copy(
            base.add(row_bytes),
            base,
            total_bytes - row_bytes,
        );
        // Clear the now-stale bottom 8-pixel row to background.
        let bg = match fb.bgr_format {
            true  => FB_TEXT_BG & 0x00FF_FFFF,
            false => {
                let r = (FB_TEXT_BG >> 16) & 0xFF;
                let g = (FB_TEXT_BG >> 8)  & 0xFF;
                let b =  FB_TEXT_BG        & 0xFF;
                (b << 16) | (g << 8) | r
            }
        };
        let bottom_start = (fb.height - 8) as usize * fb.pitch_px as usize;
        let pix          = (fb.base as *mut u32).add(bottom_start);
        let pix_count    = 8 * fb.pitch_px as usize;
        for i in 0..pix_count {
            *pix.add(i) = bg;
        }
    }
}

unsafe fn fb_text_newline(p: &mut FramebufferPainter<'_>) {
    let _ = p; // painter passed for symmetry; not used here directly
    unsafe {
        FB_TEXT_X = 0;
        if FB_TEXT_Y + 8 >= (FB_INFO.map(|f| f.height).unwrap_or(0)) {
            fb_text_scroll_one_row();
            // Cursor stays on the last row after scroll.
        } else {
            FB_TEXT_Y += 8;
        }
    }
}

/// Paint `s` on the framebuffer at the current cursor, advancing it.
/// Handles `\n` and right-edge wrapping. Non-printable bytes are skipped.
pub unsafe fn fb_text_puts(s: &[u8]) {
    unsafe {
        if !FB_TEXT_INIT {
            fb_text_clear();
        }
    }
    let mut p = match unsafe { fb_painter() } {
        Some(p) => p,
        None    => return,
    };
    for &ch in s {
        if ch == b'\n' {
            unsafe { fb_text_newline(&mut p); }
            continue;
        }
        if ch == b'\r' {
            unsafe { FB_TEXT_X = 0; }
            continue;
        }
        // Skip control chars outside the printable IBM 8x8 range.
        if ch < FONT_8X8_FIRST_CHAR {
            continue;
        }
        unsafe {
            if FB_TEXT_X + 8 > p.width {
                fb_text_newline(&mut p);
            }
            p.draw_glyph(FB_TEXT_X, FB_TEXT_Y, ch, FB_TEXT_FG, FB_TEXT_BG);
            FB_TEXT_X += 8;
        }
    }
}

/// Paint a hex u64 in the same `0xAABBCCDDEEFF0011` format as com1_puthex64.
pub unsafe fn fb_text_puthex64(v: u64) {
    let mut buf = [0u8; 18];
    buf[0] = b'0';
    buf[1] = b'x';
    for i in 0..16 {
        let nib = ((v >> (60 - i * 4)) & 0xF) as u8;
        buf[2 + i] = if nib < 10 { b'0' + nib } else { b'a' + nib - 10 };
    }
    unsafe { fb_text_puts(&buf); }
}

pub unsafe fn com1_puthex64(mut v: u64) {
    unsafe { com1_puts(b"0x"); }
    let mut buf = [0u8; 16];
    for i in 0..16 {
        let nib = ((v >> (60 - i * 4)) & 0xF) as u8;
        buf[i] = if nib < 10 { b'0' + nib } else { b'a' + nib - 10 };
    }
    let _ = &mut v;
    unsafe { com1_puts(&buf); }
}

// ─────────────────────────────────────────────────────────────────────────────
// Static aligned regions
//
// All 4 KiB-aligned via repr(C, align(4096)). They live in .bss and the UEFI
// loader marks the image's BSS pages as R/W; we keep them mapped post-EBS
// because UEFI's page tables remain in CR3 until we replace them (we don't —
// we reuse the firmware-set identity map).
// ─────────────────────────────────────────────────────────────────────────────

#[repr(C, align(4096))]
struct Page4K([u8; 4096]);

static mut VMXON_REGION:  VmxonRegion = VmxonRegion::new();
static mut VMCS_REGION:   VmcsRegion  = VmcsRegion::new();
static mut VMCB_REGION:   VmcbRegion  = VmcbRegion::new();
static mut HSAVE_REGION:  Page4K      = Page4K([0u8; 4096]);

// EPT/NPT page-table hierarchy: PML4 -> PDPT -> PD -> PT (4 levels for 4 KiB).
static mut EPT_PML4:      Page4K      = Page4K([0u8; 4096]);
static mut EPT_PDPT:      Page4K      = Page4K([0u8; 4096]);
static mut EPT_PD:        Page4K      = Page4K([0u8; 4096]);
static mut EPT_PT:        Page4K      = Page4K([0u8; 4096]);

static mut NPT_PML4:      Page4K      = Page4K([0u8; 4096]);
static mut NPT_PDPT:      Page4K      = Page4K([0u8; 4096]);
static mut NPT_PD:        Page4K      = Page4K([0u8; 4096]);
static mut NPT_PT:        Page4K      = Page4K([0u8; 4096]);

// Dedicated PD pages for the translator JIT cache + bump arena, which live
// at PA 0x2_0000_0000 (8 GiB). That falls in PDPT index 8 — distinct from
// the guest-RAM PDPT slot (index 2) — so it needs its own PD. Without
// these mappings, executing translated code at 0x2_0000_0000 would NPF
// because that GPA is above the UEFI 4 GiB identity map and not covered
// by build_npt_identity_map / build_npt_2mib_range.
static mut EPT_PD_JIT:    Page4K      = Page4K([0u8; 4096]);
static mut NPT_PD_JIT:    Page4K      = Page4K([0u8; 4096]);

// Guest page tables (4-level identity map for long-mode guest).  These live
// in HOST physical memory; the guest's CR3 points at GUEST_PML4 and the NPT
// makes that PA accessible to the guest.  Different from EPT/NPT tables
// (those are for GPA->HPA); these tables are for guest VA->guest PA.
static mut GUEST_PML4:    Page4K      = Page4K([0u8; 4096]);
static mut GUEST_PDPT:    Page4K      = Page4K([0u8; 4096]);
static mut GUEST_PD:      Page4K      = Page4K([0u8; 4096]);
static mut GUEST_PT:      Page4K      = Page4K([0u8; 4096]);

// Host stack used as VMCS_HOST_RSP. 4 KiB; grows downward.
static mut HOST_STACK:    Page4K      = Page4K([0u8; 4096]);

// Guest RAM — 4 KiB, 4 KiB-aligned.  Offset 0 holds the guest payload (a
// single HLT byte 0xF4).  Using 4 KiB EPT/NPT pages avoids the LLVM
// codegen issue triggered by 2 MiB-aligned statics in the PE32+ section
// layout for this target.
static mut GUEST_RAM:     Page4K      = Page4K([0u8; 4096]);

// ─── FEX integration regions (ch52) ──────────────────────────────────────────
// Host-only state: the FFI structs the FEX library writes into. These are
// small (kilobytes), so always allocated. The big regions — JIT cache + bump
// arena — are pulled from the UEFI memory map at runtime by the
// `fex_linked` build, never from BSS, to keep hypervisor.efi small.
#[cfg(feature = "fex_linked")]
static mut FEX_BINDINGS:  DbtHostBindings        = DbtHostBindings::new(0, 0);
#[cfg(feature = "fex_linked")]
static mut FEX_JIT_CACHE: DbtJitCache            = DbtJitCache::new(0, 0);
#[cfg(feature = "fex_linked")]
static mut FEX_AOT_QUEUE: AotPreTranslationQueue = AotPreTranslationQueue::new();

// ─── Android boot.img staging — Phase 4 ─────────────────────────────────────
// The 16 KiB BSS scan region used in Phase 0–3 has been removed. Phase 4
// expects the AETHER bootloader (or QEMU `-device loader`) to stage the
// active-slot boot.img at android_handoff::STAGED_BOOT_IMG_PA (0x80000000)
// before AETHER's hypervisor.efi runs. UEFI's identity map keeps that
// 64 MiB window accessible to EL2 / VMX root without any explicit
// AllocatePages call. See hypervisor/src/android_handoff.rs.

// ─────────────────────────────────────────────────────────────────────────────
// EPT identity map for the GUEST_RAM 2 MiB region.
//
// Intel EPT format (SDM Vol. 3C Table 28-1):
//   PML4E / PDPTE / PDE non-leaf: bits [2:0]=R/W/X, [51:12]=next-level PFN.
//   PDE leaf (2 MiB):             bits [2:0]=R/W/X, [5:3]=memtype (6=WB),
//                                  bit 7=PS=1,     [51:21]=page frame.
// ─────────────────────────────────────────────────────────────────────────────

unsafe fn build_ept_identity_map(guest_ram_pa: u64) {
    let pml4 = unsafe { &mut *(ptr::addr_of_mut!(EPT_PML4) as *mut EptTable) };
    let pdpt = unsafe { &mut *(ptr::addr_of_mut!(EPT_PDPT) as *mut EptTable) };
    let pd   = unsafe { &mut *(ptr::addr_of_mut!(EPT_PD)   as *mut EptTable) };
    let pt   = unsafe { &mut *(ptr::addr_of_mut!(EPT_PT)   as *mut EptTable) };

    let pdpt_pa = ptr::addr_of!(EPT_PDPT) as u64;
    let pd_pa   = ptr::addr_of!(EPT_PD)   as u64;
    let pt_pa   = ptr::addr_of!(EPT_PT)   as u64;

    // Indices for the 2 MiB region containing guest_ram_pa.
    let pml4_idx = ((guest_ram_pa >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((guest_ram_pa >> 30) & 0x1FF) as usize;
    let pd_idx   = ((guest_ram_pa >> 21) & 0x1FF) as usize;

    pml4.set(pml4_idx, EptTableEntry::pointing_to(pdpt_pa).0);
    pdpt.set(pdpt_idx, EptTableEntry::pointing_to(pd_pa).0);
    pd.set(pd_idx,     EptTableEntry::pointing_to(pt_pa).0);

    // Fill all 512 EPT PT entries for the 2 MiB region containing guest_ram_pa.
    // Entry: bits[2:0]=7 (R+W+X), bits[5:3]=6 (WB memtype), bits[51:12]=PFN.
    let region_base = guest_ram_pa & !0x1FFFFFu64;
    for i in 0..512usize {
        let page_pa = region_base + (i as u64) * 4096;
        pt.set(i, (page_pa & !0xFFFu64) | 0x07 | (6 << 3));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 4: EPT 2-MiB-leaf identity map for a contiguous Android handoff region.
//
// `build_ept_identity_map` above maps a single 2-MiB window using 512 × 4 KiB
// EPT-PT leaves; that is sufficient for the foundation gate's HLT byte but not
// for a 64 MiB ARM64 GKI image. This helper maps an arbitrary 2-MiB-aligned
// `[base_pa, base_pa+size_bytes)` window using 2-MiB-leaf PDE entries (Intel
// SDM Vol. 3C Table 28-2: PDE bit 7=PS=1 means leaf).
//
// Reuses the same EPT_PML4 / EPT_PDPT / EPT_PD statics as `build_ept_identity_map`;
// the existing PT chain stays in place for the GUEST_RAM 4 KiB-leaf region and
// the new 2-MiB leaves cover the boot.img + DTB span on top.
//
// SAFETY: caller must guarantee:
//   * `base_pa` and `size_bytes` are multiples of 2 MiB
//   * The full `[base_pa, base_pa+size_bytes)` window fits within a single
//     1 GiB PDPT entry that does not collide with GUEST_RAM's PD entry
//     (the helper checks the latter and refuses on collision).
unsafe fn build_ept_2mib_range(base_pa: u64, size_bytes: u64) {
    const MIB2: u64 = 2 * 1024 * 1024;
    if size_bytes == 0 || base_pa & (MIB2 - 1) != 0 || size_bytes & (MIB2 - 1) != 0 {
        unsafe { dual_puts(b"[ept2m] refuse: misaligned base/size\n"); }
        return;
    }

    let pml4 = unsafe { &mut *(ptr::addr_of_mut!(EPT_PML4) as *mut EptTable) };
    let pdpt = unsafe { &mut *(ptr::addr_of_mut!(EPT_PDPT) as *mut EptTable) };
    let pd   = unsafe { &mut *(ptr::addr_of_mut!(EPT_PD)   as *mut EptTable) };

    let pdpt_pa = ptr::addr_of!(EPT_PDPT) as u64;
    let pd_pa   = ptr::addr_of!(EPT_PD)   as u64;

    // Ensure the upper levels point at our PD tables for `base_pa`'s GPA.
    let pml4_idx = ((base_pa >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((base_pa >> 30) & 0x1FF) as usize;
    pml4.set(pml4_idx, EptTableEntry::pointing_to(pdpt_pa).0);
    pdpt.set(pdpt_idx, EptTableEntry::pointing_to(pd_pa).0);

    // Fill PD entries with 2-MiB leaves. EPT leaf format:
    //   bits[2:0] = R/W/X (set all 3 = 0x07)
    //   bits[5:3] = memtype (6 = WB)
    //   bit  7    = leaf flag (1 for 2 MiB / 1 GiB)
    //   bits[51:21] = page-frame-number << 21
    let mut pa = base_pa;
    let end = base_pa + size_bytes;
    while pa < end {
        let pd_idx = ((pa >> 21) & 0x1FF) as usize;
        let leaf = (pa & !(MIB2 - 1)) | 0x07 | (6 << 3) | (1 << 7);
        pd.set(pd_idx, leaf);
        pa += MIB2;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NPT identity map (AMD).  Same shape as EPT but AMD format.
// AMD APM Vol 2 §15.25.5.
// ─────────────────────────────────────────────────────────────────────────────

// Build a 4-level guest page table (standard x86_64) that identity-maps a
// 2 MiB region of guest VA so that VA = `guest_ram_pa` (and the page tables
// themselves) all translate to themselves.  Returns the PA to load into
// guest CR3 for long-mode VMRUN.
//
// For VA `guest_ram_pa`, the PML4/PDPT/PD/PT indices are NOT all zero —
// they depend on the high bits of the address.  We compute them and fill
// the full 2 MiB worth of PT entries (one PD slot, 512 PT slots).
unsafe fn build_guest_page_table(guest_ram_pa: u64) -> u64 {
    let pml4_va = ptr::addr_of_mut!(GUEST_PML4) as *mut u64;
    let pdpt_va = ptr::addr_of_mut!(GUEST_PDPT) as *mut u64;
    let pd_va   = ptr::addr_of_mut!(GUEST_PD)   as *mut u64;
    let pt_va   = ptr::addr_of_mut!(GUEST_PT)   as *mut u64;

    let pml4_pa = ptr::addr_of!(GUEST_PML4) as u64;
    let pdpt_pa = ptr::addr_of!(GUEST_PDPT) as u64;
    let pd_pa   = ptr::addr_of!(GUEST_PD)   as u64;
    let pt_pa   = ptr::addr_of!(GUEST_PT)   as u64;

    let pml4_idx = ((guest_ram_pa >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((guest_ram_pa >> 30) & 0x1FF) as usize;
    let pd_idx   = ((guest_ram_pa >> 21) & 0x1FF) as usize;

    // 2 MiB-aligned base of the region we identity-map in guest VA.
    let region_base = guest_ram_pa & !0x1FFFFFu64;

    unsafe {
        *pml4_va.add(pml4_idx) = (pdpt_pa & !0xFFFu64) | 0x03;
        *pdpt_va.add(pdpt_idx) = (pd_pa   & !0xFFFu64) | 0x03;
        *pd_va.add(pd_idx)     = (pt_pa   & !0xFFFu64) | 0x03;
        // Fill all 512 PT entries — covers guest_ram_pa plus the guest
        // page tables themselves (which live in the same 2 MiB region).
        for i in 0..512 {
            let page_pa = region_base + (i as u64) * 4096;
            *pt_va.add(i) = (page_pa & !0xFFFu64) | 0x03;
        }
    }

    pml4_pa
}

// Identity-map a 2 MiB region (the one containing `guest_ram_pa`) into NPT
// using 512 sequential 4 KiB PT entries.  This covers GUEST_RAM plus the
// guest page-table pages (PML4/PDPT/PD/PT) that the guest CPU walks in
// HPA space when CR3 is loaded — all of which are statics in our .bss
// allocated within a few KiB of each other.
unsafe fn build_npt_identity_map(guest_ram_pa: u64) {
    let pml4 = unsafe { &mut *(ptr::addr_of_mut!(NPT_PML4) as *mut NptTable) };
    let pdpt = unsafe { &mut *(ptr::addr_of_mut!(NPT_PDPT) as *mut NptTable) };
    let pd   = unsafe { &mut *(ptr::addr_of_mut!(NPT_PD)   as *mut NptTable) };
    let pt   = unsafe { &mut *(ptr::addr_of_mut!(NPT_PT)   as *mut NptTable) };

    let pdpt_pa = ptr::addr_of!(NPT_PDPT) as u64;
    let pd_pa   = ptr::addr_of!(NPT_PD)   as u64;
    let pt_pa   = ptr::addr_of!(NPT_PT)   as u64;

    let pml4_idx = ((guest_ram_pa >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((guest_ram_pa >> 30) & 0x1FF) as usize;
    let pd_idx   = ((guest_ram_pa >> 21) & 0x1FF) as usize;

    pml4.set(pml4_idx, NptTableEntry::pointing_to(pdpt_pa).0);
    pdpt.set(pdpt_idx, NptTableEntry::pointing_to(pd_pa).0);
    pd.set(pd_idx,     NptTableEntry::pointing_to(pt_pa).0);

    // Fill all 512 PT entries with sequential 4 KiB pages covering the 2 MiB
    // region that contains guest_ram_pa.
    let region_base = guest_ram_pa & !0x1FFFFFu64;
    for i in 0..512usize {
        let page_pa = region_base + (i as u64) * 4096;
        pt.set(i, (page_pa & !0xFFFu64) | 0x07);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 4: NPT 2-MiB-leaf identity map for the Android handoff region.
// Same shape as `build_ept_2mib_range` above but using NPT (AMD) leaf format.
// AMD APM Vol 2 §15.25.7: PDE bit 7=PS=1 means leaf; PAT/PCD/PWT memtype bits
// stay zero for default WB. R/W/X = 0x07.
unsafe fn build_npt_2mib_range(base_pa: u64, size_bytes: u64) {
    const MIB2: u64 = 2 * 1024 * 1024;
    if size_bytes == 0 || base_pa & (MIB2 - 1) != 0 || size_bytes & (MIB2 - 1) != 0 {
        unsafe { dual_puts(b"[npt2m] refuse: misaligned base/size\n"); }
        return;
    }

    let pml4 = unsafe { &mut *(ptr::addr_of_mut!(NPT_PML4) as *mut NptTable) };
    let pdpt = unsafe { &mut *(ptr::addr_of_mut!(NPT_PDPT) as *mut NptTable) };
    let pd   = unsafe { &mut *(ptr::addr_of_mut!(NPT_PD)   as *mut NptTable) };

    let pdpt_pa = ptr::addr_of!(NPT_PDPT) as u64;
    let pd_pa   = ptr::addr_of!(NPT_PD)   as u64;

    let pml4_idx = ((base_pa >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((base_pa >> 30) & 0x1FF) as usize;
    pml4.set(pml4_idx, NptTableEntry::pointing_to(pdpt_pa).0);
    pdpt.set(pdpt_idx, NptTableEntry::pointing_to(pd_pa).0);

    let mut pa = base_pa;
    let end = base_pa + size_bytes;
    while pa < end {
        let pd_idx = ((pa >> 21) & 0x1FF) as usize;
        // NPT leaf: P=1 (bit 0), R/W=1 (bit 1), U/S=1 (bit 2) — 0x07 — plus
        // PS=1 (bit 7). Default WB memtype (PAT=PCD=PWT=0). NX=0.
        let leaf = (pa & !(MIB2 - 1)) | 0x07 | (1 << 7);
        pd.set(pd_idx, leaf);
        pa += MIB2;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// JIT cache mapping helpers — EPT (Intel) and NPT (AMD).
//
// The translator JIT cache + bump arena live at PA 0x2_0000_0000 (8 GiB) /
// 0x2_0100_0000. That falls in PDPT index 8 for both PML4 trees, which is
// distinct from the guest-RAM PDPT slot (index 2 for 0x8000_0000). So the
// existing EPT_PD / NPT_PD statics — already chained under PDPT[2] — can
// not be reused; we need dedicated PD pages (EPT_PD_JIT / NPT_PD_JIT) so
// that PDPT[8] points somewhere valid.
//
// W^X is enforced post-mapping: the page starts RWX, then commit_rx_via_ept
// (registered by install_dbt_ept_callbacks) flips individual 2-MiB leaves
// from RW to RX as the translator commits new blocks. The initial RWX is
// safe because the guest has no path to GPA 0x2_0000_0000 — the guest CR3
// only walks the guest page table built by build_guest_page_table around
// guest_ram_pa, which lives at PDPT[2], not PDPT[8].
//
// SAFETY: caller must guarantee `base_pa` and `size_bytes` are 2-MiB
// multiples, and that the entire window fits within a single PDPT entry
// (i.e. less than 1 GiB and not straddling a 1-GiB boundary).
unsafe fn build_ept_2mib_jit_range(base_pa: u64, size_bytes: u64) {
    const MIB2: u64 = 2 * 1024 * 1024;
    if size_bytes == 0 || base_pa & (MIB2 - 1) != 0 || size_bytes & (MIB2 - 1) != 0 {
        unsafe { dual_puts(b"[ept-jit] refuse: misaligned base/size\n"); }
        return;
    }

    let pml4 = unsafe { &mut *(ptr::addr_of_mut!(EPT_PML4)   as *mut EptTable) };
    let pdpt = unsafe { &mut *(ptr::addr_of_mut!(EPT_PDPT)   as *mut EptTable) };
    let pd   = unsafe { &mut *(ptr::addr_of_mut!(EPT_PD_JIT) as *mut EptTable) };

    let pdpt_pa   = ptr::addr_of!(EPT_PDPT)   as u64;
    let pd_jit_pa = ptr::addr_of!(EPT_PD_JIT) as u64;

    let pml4_idx = ((base_pa >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((base_pa >> 30) & 0x1FF) as usize;
    pml4.set(pml4_idx, EptTableEntry::pointing_to(pdpt_pa).0);
    pdpt.set(pdpt_idx, EptTableEntry::pointing_to(pd_jit_pa).0);

    // EPT leaf: R/W/X = 0x07, memtype WB = 6 << 3, PS = bit 7.
    let mut pa = base_pa;
    let end = base_pa + size_bytes;
    while pa < end {
        let pd_idx = ((pa >> 21) & 0x1FF) as usize;
        let leaf = (pa & !(MIB2 - 1)) | 0x07 | (6 << 3) | (1 << 7);
        pd.set(pd_idx, leaf);
        pa += MIB2;
    }
}

unsafe fn build_npt_2mib_jit_range(base_pa: u64, size_bytes: u64) {
    const MIB2: u64 = 2 * 1024 * 1024;
    if size_bytes == 0 || base_pa & (MIB2 - 1) != 0 || size_bytes & (MIB2 - 1) != 0 {
        unsafe { dual_puts(b"[npt-jit] refuse: misaligned base/size\n"); }
        return;
    }

    let pml4 = unsafe { &mut *(ptr::addr_of_mut!(NPT_PML4)   as *mut NptTable) };
    let pdpt = unsafe { &mut *(ptr::addr_of_mut!(NPT_PDPT)   as *mut NptTable) };
    let pd   = unsafe { &mut *(ptr::addr_of_mut!(NPT_PD_JIT) as *mut NptTable) };

    let pdpt_pa   = ptr::addr_of!(NPT_PDPT)   as u64;
    let pd_jit_pa = ptr::addr_of!(NPT_PD_JIT) as u64;

    let pml4_idx = ((base_pa >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((base_pa >> 30) & 0x1FF) as usize;
    pml4.set(pml4_idx, NptTableEntry::pointing_to(pdpt_pa).0);
    pdpt.set(pdpt_idx, NptTableEntry::pointing_to(pd_jit_pa).0);

    // NPT leaf: P|R/W|U/S = 0x07, PS=bit 7, WB default, NX=0.
    let mut pa = base_pa;
    let end = base_pa + size_bytes;
    while pa < end {
        let pd_idx = ((pa >> 21) & 0x1FF) as usize;
        let leaf = (pa & !(MIB2 - 1)) | 0x07 | (1 << 7);
        pd.set(pd_idx, leaf);
        pa += MIB2;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Host VMEXIT handler (Intel path)
//
// vmcs_write_host_state writes host_rip = address of this function. The
// processor jumps here on every VMEXIT with:
//   - All host state restored from VMCS host fields (CR0/CR3/CR4/EFER, ...).
//   - RSP = VMCS_HOST_RSP (our HOST_STACK top).
//   - Interrupts disabled (RFLAGS.IF=0).
//
// We do not VMRESUME here — we read the exit reason via VMREAD, print it,
// and HLT. That is the Ch50 gate: "first VMEXIT observed."
// ─────────────────────────────────────────────────────────────────────────────

// Host VMEXIT entry — written by VMCS_HOST_RIP.  CPU jumps here on VMEXIT
// with all host state restored from VMCS host fields (CR0/CR3/CR4, segments,
// EFER, RSP).  Interrupts are masked.
//
// Phase 5 dispatch:
//   1. VMREAD exit_reason + exit_qualification + guest-physical-address.
//   2. dbt_dispatch::classify_intel → DbtExitClass.
//   3. If FEX dispatch is armed (Android handoff completed), call
//      dbt_dispatch::handle_vmexit and either VMRESUME (Reenter) or HALT.
//   4. Otherwise the foundation gate path: log + HALT (Ch50/51 behaviour).
//
// VMRESUME is NOT yet wired — see TODO Phase 5b. For now Reenter falls
// through to halt with a diagnostic noting the missing re-entry.
#[unsafe(no_mangle)]
unsafe extern "C" fn host_vmexit_entry() -> ! {
    unsafe {
        const VMCS_EXIT_REASON:           u32 = 0x4402;
        const VMCS_EXIT_QUALIFICATION:    u32 = 0x6400;
        const VMCS_GUEST_PHYSICAL_ADDRESS:u32 = 0x2400;

        let (exit_reason, _) = vmread(VMCS_EXIT_REASON);
        let (exit_qual,    _) = vmread(VMCS_EXIT_QUALIFICATION);
        let (gpa,          _) = vmread(VMCS_GUEST_PHYSICAL_ADDRESS);

        dual_puts(b"[x86] VMEXIT reason=");
        dual_puthex64(exit_reason);
        if exit_reason & (1u64 << 31) != 0 {
            dual_puts(b" (VM-entry failure)\n");
            dual_puts(b"[x86] halting.\n");
            loop { core::arch::asm!("cli; hlt", options(nomem, nostack)); }
        }
        let basic = (exit_reason & 0xFFFF) as u32;
        match basic {
            0x0C => dual_puts(b" HLT\n"),
            0x00 => dual_puts(b" EXCEPTION_NMI\n"),
            0x01 => dual_puts(b" EXTERNAL_INTERRUPT\n"),
            0x30 => { dual_puts(b" EPT_VIOLATION gpa="); dual_puthex64(gpa); dual_puts(b"\n"); }
            _    => dual_puts(b"\n"),
        }

        // Phase 5/5b dispatch path — only when boot path armed the FEX state.
        if crate::dbt_dispatch::is_armed() {
            let exit = crate::dbt_dispatch::classify_intel(basic, exit_qual, gpa);
            let action = crate::dbt_dispatch::with_global_mut(|s| {
                crate::dbt_dispatch::handle_vmexit(s, exit)
            });
            match action {
                crate::dbt_dispatch::VmexitAction::Reenter => {
                    // Phase 5b: issue VMRESUME. On success the CPU transfers
                    // back to GUEST_RIP and the next VMEXIT will land here
                    // again. On failure (invalid VMCS / illegal transition)
                    // VMRESUME returns control and we fall through to halt.
                    let ok = crate::vtx::vmresume();
                    if !ok {
                        const VMCS_VM_INSTR_ERROR: u32 = 0x4400;
                        let (err, _) = vmread(VMCS_VM_INSTR_ERROR);
                        dual_puts(b"[fex] VMRESUME failed; VM_INSTR_ERROR=");
                        dual_puthex64(err);
                        dual_puts(b"\n");
                    } else {
                        // Unreachable in the success case — VMRESUME does
                        // not return. Emitting this line is dead code that
                        // documents the contract.
                        dual_puts(b"[fex] VMRESUME unexpectedly returned\n");
                    }
                }
                crate::dbt_dispatch::VmexitAction::Halt => {
                    dual_puts(b"[fex] dispatch -> Halt\n");
                }
            }
        }

        dual_puts(b"[x86] Hypervisor in VMX root mode. Halting.\n");
        loop { core::arch::asm!("cli; hlt", options(nomem, nostack)); }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Top-level x86 boot pipeline.
// ─────────────────────────────────────────────────────────────────────────────

pub unsafe fn boot_x86_hypervisor(
    image_handle: *mut c_void,
    system_table: *const c_void,
    vendor: Option<CpuVendor>,
) -> ! {
    // ── 0. ESP file-protocol shim — runs while firmware boot services are
    //       still alive. Reads \EFI\AETHER\boot.img into the staged region
    //       at STAGED_BOOT_IMG_PA so prepare_android_handoff() finds the
    //       "ANDROID!" magic there post-ExitBootServices.
    //
    //       Best-effort: if no boot.img is on the ESP the pipeline falls
    //       back to the foundation gate (single HLT in GUEST_RAM).
    {
        use crate::android_handoff::STAGED_BOOT_IMG_SIZE;
        use crate::boot_x86_esp::try_read_boot_img_alloc;
        // Audit §2a fix: ask UEFI to allocate the staging buffer rather
        // than writing into a fixed PA (0x8000_0000) that on this Ryzen
        // board may not be conventional memory. AllocatePages with
        // MaxAddress < 4 GiB ensures the result is reachable from both
        // pre-EBS firmware page tables and our post-EBS identity NPT.
        const STAGE_PAGES: usize = (STAGED_BOOT_IMG_SIZE / 4096) as usize; // 16384
        const MAX_PA_4GIB: u64 = 0xFFFF_FFFF;
        // SAFETY: image_handle + system_table came from efi_main and are
        // still valid before ExitBootServices.
        let (alloc_pa, read) = unsafe {
            try_read_boot_img_alloc(
                image_handle as *mut _,
                system_table as *const EfiSystemTable,
                STAGE_PAGES,
                MAX_PA_4GIB,
            )
        };
        // Pre-EBS audible signal — distinct from any post-EBS bisect pitch.
        //
        //   2 KiloHz short beeps × 2  = boot.img LOADED successfully
        //   300 Hz   long  beep × 1  = boot.img MISSING / read failed
        //                              (foundation-gate fallback path)
        //
        // PIT speaker is hardware-only — works pre-EBS, post-EBS, anywhere.
        // The user hears this BEFORE the GREEN flash so it's easy to tell
        // apart from the rest of the boot ladder.
        unsafe {
            if read > 0 {
                beep_once(2000);
                beep_once(2000);
            } else {
                // Long low tone — extends to ~300 ms by chaining frequency 300.
                beep_once(300);
            }
        }
        // Stash the ESP error so we can print it AFTER ExitBootServices via
        // dual_puts (printing while boot services are still alive is fine,
        // but we want it in the post-EBS log next to the other diagnostics).
        let (esp_err_kind, esp_err_status) = crate::boot_x86_esp::last_esp_error();
        unsafe {
            STAGED_ESP_ERR_KIND   = esp_err_kind;
            STAGED_ESP_ERR_STATUS = esp_err_status;
            STAGED_ESP_READ_BYTES = read;
            STAGED_ALLOC_PA       = alloc_pa;
        }
    }

    // ── 1. ExitBootServices (capture RSDP first; same as ARM path) ───────────
    let boot_ctx = unsafe {
        BootContext::from_uefi(
            image_handle as *mut _,
            system_table as *const EfiSystemTable,
        )
    };
    let _boot_result = unsafe { boot_ctx.run() };

    // Diagnostic beep ladder — temporary, while we figure out why the
    // last Ryzen boot went from "1 long beep (boot.img missing) → RED"
    // with no post-EBS text visible. Each tone bisects one stage of
    // post-EBS bring-up that runs BEFORE the framebuffer text painter.
    // Hearing tone N but not N+1 pins the failing stage.
    //   500 Hz  = boot_ctx.run() returned (EBS succeeded)
    //   700 Hz  = just before first dual_puts (FB text painter first try)
    //   900 Hz  = just after first dual_puts (FB text painter survived)
    //  1100 Hz  = vendor branch entered (boot_amd / boot_intel reached)
    //  1300 Hz  = just before init_svm_foundation / init_vtx_foundation
    //  1500 Hz  = foundation init returned (about to VMRUN/VMLAUNCH)
    unsafe { beep_once(500); }

    // ── 2. ConOut is dead. Switch to COM1 + VGA text mode + paint screen. ───
    unsafe {
        com1_init();
        vga_clear();
        // Removed: checkpoint(FB_GREEN, 1, 880). fb_fill paints the whole
        // screen one solid color, which wipes every dual_puts line that
        // follows. With the new fb_text_puts wired into dual_puts the
        // text-mode "[x86] ExitBootServices: OK" is now the visible
        // confirmation. Pre-EBS probe beeps above and the RED halt-loop
        // flash below are kept as last-resort audible signals.
        beep_once(700);
        dual_puts(b"\n[x86] ExitBootServices: OK\n");
        beep_once(900);

        // Phase-D: ensure the handoff RAM range is host-writable. OVMF's
        // identity map sometimes leaves staged-RAM ranges as W=0 leaves
        // (or maps large pages with W=0 covering ranges we need to write
        // into via lifted ARM64 stores). Walk the host CR3 and OR-in
        // PTE.W on every leaf covering the staged boot.img + handoff
        // window. Safer than clearing CR0.WP (which would let buggy lifted
        // stores corrupt hypervisor .text).
        host_pt_make_handoff_rw();

        // Surface the pre-EBS boot.img read result. Kinds:
        //   0=ok, 1=LoadedImage missing, 2=no FS on device, 3=OpenVolume failed,
        //   4=Open file failed (path wrong / file missing on FAT32),
        //   5=Read failed, 6=buffer too small.
        // EfiStatus codes:
        //   0x800…00E = EFI_NOT_FOUND  → file genuinely absent
        //   0x800…00F = EFI_NO_MEDIA   → device not ready
        //   0x800…002 = EFI_INVALID_PARAMETER
        //   0x800…00D = EFI_VOLUME_CORRUPTED
        dual_puts(b"[esp] boot.img read bytes=");
        dual_puthex64(STAGED_ESP_READ_BYTES as u64);
        dual_puts(b" err_kind=");
        dual_puthex64(STAGED_ESP_ERR_KIND as u64);
        dual_puts(b" status=");
        dual_puthex64(STAGED_ESP_ERR_STATUS as u64);
        dual_puts(b"\n");
    }

    // ── 3. Compute physical addresses of our static regions ─────────────────
    // UEFI leaves CR3 = firmware page tables (identity map for the lower 4 GiB
    // on every UEFI implementation that ships an x86_64 firmware).  Therefore
    // virtual address == physical address for all .bss statics in our image.
    let vmxon_pa     = ptr::addr_of!(VMXON_REGION) as u64;
    let vmcs_pa      = ptr::addr_of!(VMCS_REGION)  as u64;
    let vmcb_pa      = ptr::addr_of!(VMCB_REGION)  as u64;
    let hsave_pa     = ptr::addr_of!(HSAVE_REGION) as u64;
    let ept_pml4_pa  = ptr::addr_of!(EPT_PML4)     as u64;
    let npt_pml4_pa  = ptr::addr_of!(NPT_PML4)     as u64;
    let guest_ram_pa = ptr::addr_of!(GUEST_RAM)    as u64;
    let host_stack_top =
        ptr::addr_of!(HOST_STACK) as u64 + 4096u64;
    let host_rip     = host_vmexit_entry as *const () as u64;

    unsafe {
        dual_puts(b"[x86] VMXON region PA = "); dual_puthex64(vmxon_pa); dual_puts(b"\n");
        dual_puts(b"[x86] VMCS region PA  = "); dual_puthex64(vmcs_pa);  dual_puts(b"\n");
        dual_puts(b"[x86] EPT PML4 PA     = "); dual_puthex64(ept_pml4_pa); dual_puts(b"\n");
        dual_puts(b"[x86] Guest RAM PA    = "); dual_puthex64(guest_ram_pa); dual_puts(b"\n");
        dual_puts(b"[x86] Host RIP        = "); dual_puthex64(host_rip);  dual_puts(b"\n");
        // bisect(2): now redundant — the dual_puts above already tells
        // the user we reached this stage on the framebuffer.
    }

    // ── 4. Stage guest payload — Phase 4 Android handoff or foundation gate ─
    //
    // Priority order:
    //   (a) FEX-linked + boot.img staged at STAGED_BOOT_IMG_PA → prepare full
    //       Android handoff: scan boot.img, build DTB, synth FEX initial GPRs,
    //       extend EPT/NPT to cover the handoff region, set kernel_entry_pa to
    //       layout.kernel_pa. Phase 5 (FEX dispatch) consumes from there.
    //   (b) boot.img staged but FEX absent → handoff still happens (so the
    //       Phase 3 gate `boot_magic_readable` flips) but the guest payload
    //       falls back to a HLT byte so the foundation gate still produces a
    //       VMEXIT.
    //   (c) Nothing staged → single HLT byte (Ch50/51 foundation-gate behaviour).
    // Choose which staging PA to scan. If the UEFI AllocatePages reader
    // succeeded, prefer that PA — it's guaranteed conventional RAM by
    // firmware contract. Otherwise fall back to the legacy fixed PA so
    // synthetic/test images that pre-stage at 0x8000_0000 still work.
    let (stage_pa, stage_size) = {
        let alloc_pa = unsafe { STAGED_ALLOC_PA };
        if alloc_pa != 0 {
            // UEFI gave us at least STAGED_BOOT_IMG_SIZE bytes at this PA.
            (alloc_pa, crate::android_handoff::STAGED_BOOT_IMG_SIZE)
        } else {
            (crate::android_handoff::STAGED_BOOT_IMG_PA,
             crate::android_handoff::STAGED_BOOT_IMG_SIZE)
        }
    };
    // Dump first 16 bytes at the chosen PA so the post-mortem photo shows
    // whether the firmware actually deposited "ANDROID!" magic there.
    // Expected v3/v4 first u64 = 0x21444E494F52444E ("ANDROID!" LE).
    unsafe {
        let p = stage_pa as *const u64;
        let w0 = core::ptr::read_volatile(p);
        let w1 = core::ptr::read_volatile(p.add(1));
        dual_puts(b"[stage] PA=");
        dual_puthex64(stage_pa);
        dual_puts(b" alloc=");
        dual_puthex64(STAGED_ALLOC_PA);
        dual_puts(b"\n[stage] first16=");
        dual_puthex64(w0);
        dual_puts(b" ");
        dual_puthex64(w1);
        dual_puts(b" (want 0x21444E494F52444E ...)\n");
    }
    // For the DTB: keep using GUEST_DTB_PA which lives in our own BSS-
    // adjacent identity range. (The UEFI alloc only covered the boot.img
    // window; GUEST_DTB_PA = STAGED_BOOT_IMG_PA + STAGED_BOOT_IMG_SIZE,
    // which is unrelated when we allocated dynamically.) Allocate the
    // DTB explicitly: hand it the page immediately after the boot.img
    // window in our alloc, OR fall back to the constant.
    let (dtb_pa, region_size) = {
        let alloc_pa = unsafe { STAGED_ALLOC_PA };
        if alloc_pa != 0 {
            // Place DTB right after the boot.img window. UEFI alloc gave
            // us STAGE_PAGES + 512 pages = 66 MiB, minus 2 MiB lost to
            // alignment — leaves ≥ 64 MiB. The DTB is small (8 KiB) so
            // 64 MiB + slack fits both comfortably as a single region.
            // The region the NPT will map is the boot.img window only;
            // DTB lives just above it.
            let dtb = alloc_pa + crate::android_handoff::STAGED_BOOT_IMG_SIZE;
            let total = crate::android_handoff::STAGED_BOOT_IMG_SIZE
                      + crate::android_handoff::GUEST_DTB_SIZE
                      + crate::android_handoff::KERNEL_WORKING_RAM_SIZE;
            (dtb, total)
        } else {
            (crate::android_handoff::GUEST_DTB_PA,
             crate::android_handoff::HANDOFF_REGION_SIZE)
        }
    };

    let handoff: Option<AndroidHandoff> = unsafe {
        match prepare_android_handoff_at(
            stage_pa,
            stage_size,
            dtb_pa,
            crate::android_handoff::GUEST_DTB_SIZE,
            region_size,
        ) {
            Ok(h) => {
                dual_puts(b"[android] boot.img found at PA=");
                dual_puthex64(h.layout.header_pa);
                dual_puts(b" kernel_pa=");
                dual_puthex64(h.layout.kernel_pa);
                dual_puts(b" kernel_size=");
                dual_puthex64(h.layout.kernel_size as u64);
                dual_puts(b"\n");
                dual_puts(b"[android] DTB PA=");
                dual_puthex64(h.dtb_pa);
                dual_puts(b" len=");
                dual_puthex64(h.dtb_len as u64);
                dual_puts(b" FEX x0=");
                dual_puthex64(h.dbt_regs.x[0]);
                dual_puts(b"\n");
                // A.1: dump the full 40-byte FDT v17 header with per-field
                // decoding so we can diff against libfdt's fdt_check_header
                // requirements. Linux rejects the DTB silently (no earlycon
                // yet) if any of: magic != 0xD00DFEED, version not in
                // [16,17], last_comp_version > 17, off_dt_struct +
                // size_dt_struct > totalsize, off_dt_strings + size_dt_strings
                // > totalsize, off_mem_rsvmap + 16 > off_dt_struct, or any
                // offset not 8-byte aligned.
                {
                    let dtb = h.dtb_pa as *const u8;
                    let r32 = |off: usize| -> u32 {
                        let b0 = *dtb.add(off) as u32;
                        let b1 = *dtb.add(off + 1) as u32;
                        let b2 = *dtb.add(off + 2) as u32;
                        let b3 = *dtb.add(off + 3) as u32;
                        (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
                    };
                    let magic = r32(0);
                    let totalsize = r32(4);
                    let off_struct = r32(8);
                    let off_strings = r32(12);
                    let off_rsvmap = r32(16);
                    let version = r32(20);
                    let last_comp = r32(24);
                    let boot_cpu = r32(28);
                    let sz_strings = r32(32);
                    let sz_struct = r32(36);
                    dual_puts(b"[fdt] magic=");
                    dual_puthex64(magic as u64);
                    dual_puts(b" totalsize=");
                    dual_puthex64(totalsize as u64);
                    dual_puts(b" off_struct=");
                    dual_puthex64(off_struct as u64);
                    dual_puts(b" off_strings=");
                    dual_puthex64(off_strings as u64);
                    dual_puts(b"\n[fdt] off_rsvmap=");
                    dual_puthex64(off_rsvmap as u64);
                    dual_puts(b" version=");
                    dual_puthex64(version as u64);
                    dual_puts(b" last_comp=");
                    dual_puthex64(last_comp as u64);
                    dual_puts(b" boot_cpu=");
                    dual_puthex64(boot_cpu as u64);
                    dual_puts(b" sz_strings=");
                    dual_puthex64(sz_strings as u64);
                    dual_puts(b" sz_struct=");
                    dual_puthex64(sz_struct as u64);
                    dual_puts(b"\n[fdt] checks:");
                    let mut ok = true;
                    if magic != 0xD00D_FEED { dual_puts(b" BAD_MAGIC"); ok = false; }
                    if !(16..=17).contains(&version) { dual_puts(b" BAD_VERSION"); ok = false; }
                    if last_comp > 17 { dual_puts(b" BAD_LASTCOMP"); ok = false; }
                    if off_rsvmap + 16 > off_struct { dual_puts(b" RSVMAP_OVERLAPS_STRUCT"); ok = false; }
                    if off_struct + sz_struct > totalsize { dual_puts(b" STRUCT_OOB"); ok = false; }
                    if off_strings + sz_strings > totalsize { dual_puts(b" STRINGS_OOB"); ok = false; }
                    if off_struct % 4 != 0 { dual_puts(b" STRUCT_UNALIGNED"); ok = false; }
                    if off_rsvmap % 8 != 0 { dual_puts(b" RSVMAP_UNALIGNED"); ok = false; }
                    if (totalsize as usize) != h.dtb_len { dual_puts(b" TOTALSIZE_NE_DTB_LEN"); ok = false; }
                    if ok { dual_puts(b" PASS"); }
                    dual_puts(b"\n[android] initrd: start=");
                    dual_puthex64(h.layout.ramdisk_pa);
                    dual_puts(b" size=");
                    dual_puthex64(h.layout.ramdisk_size as u64);
                    dual_puts(b"\n");
                }
                if h.kernel_decompressed {
                    dual_puts(b"[android] kernel gunzip'd -> entry_pa=");
                    dual_puthex64(h.layout.kernel_pa);
                    dual_puts(b" size=");
                    dual_puthex64(h.layout.kernel_size as u64);
                    dual_puts(b"\n");
                } else {
                    dual_puts(b"[android] kernel uncompressed (in-place Image)\n");
                }
                Some(h)
            }
            Err(HandoffError::BootImgNotFound) => {
                dual_puts(b"[android] handoff fail: BootImgNotFound (ANDROID! magic not at STAGED_BOOT_IMG_PA)\n");
                None
            }
            Err(HandoffError::InvalidHeader) => {
                dual_puts(b"[android] handoff fail: InvalidHeader (magic present but v3/v4 fields rejected)\n");
                None
            }
            Err(HandoffError::KernelOutOfRange) => {
                dual_puts(b"[android] handoff fail: KernelOutOfRange (kernel_size > staged region)\n");
                None
            }
            Err(HandoffError::DtbTooLarge) => {
                dual_puts(b"[android] handoff fail: DtbTooLarge (emitted DTB > GUEST_DTB_SIZE)\n");
                None
            }
            Err(HandoffError::DtbBuild(_)) => {
                dual_puts(b"[android] handoff fail: DtbBuild (kernel.rs DtbBuilder error)\n");
                None
            }
            Err(HandoffError::KernelDecompressFailed) => {
                dual_puts(b"[android] handoff fail: KernelDecompressFailed (gzip stream corrupt or > region)\n");
                None
            }
            Err(HandoffError::KernelCompressionUnsupported) => {
                dual_puts(b"[android] handoff fail: KernelCompressionUnsupported (only raw Image + gzip Image.gz)\n");
                None
            }
            Err(HandoffError::KernelDecompressNoRoom) => {
                dual_puts(b"[android] handoff fail: KernelDecompressNoRoom (no space above DTB in mapped region)\n");
                None
            }
        }
    };
    // bisect(3) removed — dual_puts above already prints the boot.img /
    // handoff status; an audible tone here added nothing.

    let fex_ok = unsafe { try_init_fex() };

    unsafe {
        // Arming criterion: handoff.is_some() — the translator runtime is
        // initialized by translator_dbt_init() unconditionally (see boot_amd
        // / boot_intel below), so we don't need the upstream FEX library
        // (fex_linked Cargo feature) to be present in order to run the
        // dispatch loop. The fex_ok flag now only gates whether the
        // additional Ch52 hypervisor-side bookkeeping (init_dbt_integration_hv)
        // ran — useful for the AT-26 fingerprint gate but not required to
        // translate a single ARM64 block.
        //
        // Without this relaxation, every boot would foundation-gate as long
        // as the build doesn't pass --features fex_linked, even with a fully
        // staged boot.img — which is the exact failure mode the May 2026
        // Ryzen test caught.
        if handoff.is_some() {
            if fex_ok {
                dual_puts(b"[x86] FEX ready + handoff prepared - Android dispatch armed\n");
            } else {
                dual_puts(b"[x86] handoff prepared - translator-only dispatch armed (no fex_linked)\n");
            }
            // Phase 5: arm the FEX dispatch state with the handoff's initial
            // ARM64 registers. host_vmexit_entry then drives the translate /
            // dispatch / classify loop on every exit.
            if let Some(ref h) = handoff {
                crate::dbt_dispatch::arm_global(h.dbt_regs);
                // Pin the live guest-RAM window to the REAL handoff span (the
                // same (region_pa, region_size) the EPT/NPT maps via
                // `extra_region`). On the UEFI-alloc path this is near 4 GiB,
                // NOT the STAGED_BOOT_IMG_PA constant — see DISPATCH_WINDOW_*.
                unsafe {
                    DISPATCH_WINDOW_BASE = h.region_pa;
                    DISPATCH_WINDOW_SIZE = h.region_size;
                }
            }
            // Phase 6: initialise the Android lifecycle scanner so PL011 DR
            // writes from the guest land in userspace_boot + app_compat
            // diagnostic state.
            crate::android_runtime::init_global();
            // 4-ascending-beep FEX-armed signal removed — the dual_puts
            // banner above now prints the same information on the
            // framebuffer.
        } else {
            // Fallback: foundation-gate payload — a HLT at GUEST_RAM_PA.
            let guest = ptr::addr_of_mut!(GUEST_RAM) as *mut u8;
            *guest = 0xF4;
            dual_puts(b"[x86] foundation-gate fallback (no FEX/handoff)\n");
            // 2-falling-beep foundation-gate signal removed — see above.
        }
        // bisect(4) removed.
    }

    // ── 5. Branch on vendor ─────────────────────────────────────────────────
    // kernel_entry_pa / extra_region used to be gated on `fex_ok` — that
    // was wrong: the translator runtime (Step A pipeline) is initialized
    // by translator_dbt_init() unconditionally and does NOT require the
    // upstream libfex.a, so once the handoff prepared a real kernel we
    // should jump to it. `fex_linked` only controls the optional FEX-AOT
    // path which is bookkeeping, not the dispatch path itself.
    let kernel_entry_pa = match &handoff {
        Some(h) => h.layout.kernel_pa,
        None    => guest_ram_pa,
    };
    let extra_region: Option<(u64, u64)> = handoff.as_ref()
        .map(|h| (h.region_pa, h.region_size));
    let _ = fex_ok; // intentionally not gating the dispatch path

    match vendor {
        Some(CpuVendor::Intel) => unsafe { boot_intel(
            vmxon_pa, vmcs_pa, ept_pml4_pa, guest_ram_pa,
            host_stack_top, host_rip, kernel_entry_pa, extra_region,
        ) },
        Some(CpuVendor::Amd) => unsafe {
            beep_once(1100); // diagnostic: vendor branch entered (AMD)
            boot_amd(
            vmcb_pa, hsave_pa, npt_pml4_pa, guest_ram_pa,
            kernel_entry_pa, extra_region,
        ) },
        None => {
            unsafe { dual_puts(b"[x86] Unsupported CPU vendor. Halting.\n"); }
            halt();
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Intel: VMXON -> init_vtx_foundation -> VMLAUNCH
// ─────────────────────────────────────────────────────────────────────────────

unsafe fn boot_intel(
    vmxon_pa: u64,
    vmcs_pa: u64,
    ept_pml4_pa: u64,
    guest_ram_pa: u64,
    host_stack_top: u64,
    host_rip: u64,
    kernel_entry_pa: u64,
    extra_region: Option<(u64, u64)>,
) -> ! {
    unsafe {
        dual_puts(b"[x86] Intel path: building EPT identity map...\n");
        build_ept_identity_map(guest_ram_pa);
        if let Some((base, size)) = extra_region {
            dual_puts(b"[x86] EPT 2-MiB map for Android handoff: base=");
            dual_puthex64(base);
            dual_puts(b" size=");
            dual_puthex64(size);
            dual_puts(b"\n");
            build_ept_2mib_range(base, size);
        }
        let guest_cr3 = build_guest_page_table(guest_ram_pa);
        dual_puts(b"[x86] Guest CR3 (PML4)= "); dual_puthex64(guest_cr3); dual_puts(b"\n");
        dual_puts(b"[x86] kernel_entry_pa = "); dual_puthex64(kernel_entry_pa); dual_puts(b"\n");

        // When the kernel entry sits inside the handoff region the foundation
        // config still advertises GUEST_RAM as the primary 2-MiB window for
        // CR3 / stack reachability. EPT covers the kernel via the extra
        // 2-MiB-leaf range above.
        let cfg = VtxFoundationConfig {
            vmxon_pa,
            vmcs_pa,
            ept_pml4_pa,
            kernel_entry_pa,
            guest_ram_base:  guest_ram_pa,
            // 1 GiB guest RAM window. 4 KiB was the original ch50 foundation-
            // gate value used only to fire one HLT-VMEXIT — it OOM's any real
            // Android kernel before init even runs. The actual mapped span is
            // controlled by `extra_region` (HANDOFF_REGION_SIZE for Android),
            // but this field is what the VtxFoundationConfig::validate() check
            // and a handful of downstream EPT-violation handlers compare GPAs
            // against, so it must reflect the real accessible window.
            guest_ram_size:  1024 * 1024 * 1024,
            mmio_base:       0,
            mmio_size:       0,
            guest_64bit:     true,         // long mode -> simpler VMCB
        };

        dual_puts(b"[x86] init_vtx_foundation()...\n");
        let vmxon = &mut *(ptr::addr_of_mut!(VMXON_REGION));
        let vmcs  = &mut *(ptr::addr_of_mut!(VMCS_REGION));
        match init_vtx_foundation(&cfg, vmxon, vmcs, host_stack_top, host_rip) {
            Ok(state) => {
                dual_puts(b"[x86] init_vtx_foundation: phase=");
                dual_puthex64(state.phase as u64);
                dual_puts(b" (EPT active)\n");
            }
            Err(_) => {
                dual_puts(b"[x86] init_vtx_foundation FAILED. Check BIOS VT-x.\n");
                halt();
            }
        }

        // Patch the guest CR3 the foundation init hardcoded to 0.
        let _ = vmwrite(VMCS_GUEST_CR3, guest_cr3);

        // Publish the active EPT root + EPTP to the W^X subsystem and
        // install the translator's commit_rx_via_ept callback. After this
        // point any aether_dbt_translate_block that emits into the JIT
        // arena will flip the corresponding host PA from RW to RX via the
        // active EPT and trigger INVEPT single-context — fulfilling the
        // Step 3 invariant on every translated block.
        set_active_ept(ept_pml4_pa, Eptp::from_pml4_pa(ept_pml4_pa));
        install_dbt_ept_callbacks();
        dual_puts(b"[x86] EPT W^X callback installed (PML4 = ");
        dual_puthex64(ept_pml4_pa);
        dual_puts(b")\n");

        // Initialise the translator runtime with the hypervisor-private JIT
        // arena. After this point, the EPT-violation-on-fetch bridge in
        // vtx::handle_vm_exit can decode + lift + lower guest ARM64 to real
        // x86 bytes (Step A of the AT integration plan).
        const JIT_CACHE_BASE_PA: u64 = 0x2_0000_0000;
        const BUMP_ARENA_BASE_PA: u64 = 0x2_0100_0000;
        const BUMP_ARENA_BYTES: usize = 1 * 1024 * 1024;
        // Map the JIT cache + bump arena into the active EPT before the
        // translator emits any code. JIT lives at PDPT idx 8 (8 GiB),
        // well above the UEFI 4 GiB identity map, so without this call
        // the first JMP into translated code would EPT-violate. 32 MiB
        // covers 16 MiB JIT + 1 MiB bump arena with headroom for growth.
        const JIT_NPT_MAP_BYTES: u64 = 32 * 1024 * 1024;
        build_ept_2mib_jit_range(JIT_CACHE_BASE_PA, JIT_NPT_MAP_BYTES);
        dual_puts(b"[x86] EPT JIT region mapped: base=");
        dual_puthex64(JIT_CACHE_BASE_PA);
        dual_puts(b" size=");
        dual_puthex64(JIT_NPT_MAP_BYTES);
        dual_puts(b"\n");
        let _ = translator_dbt_init(
            JIT_CACHE_BASE_PA,
            TRANSLATOR_JIT_BYTES,
            BUMP_ARENA_BASE_PA,
            BUMP_ARENA_BYTES,
        );
        dual_puts(b"[x86] translator runtime initialised (JIT = ");
        dual_puthex64(JIT_CACHE_BASE_PA);
        dual_puts(b")\n");

        // M4b-5: a real kernel (handoff armed) runs through the vendor-neutral
        // HOST-MODE dispatch loop — Intel and AMD share it. We do NOT VMLAUNCH
        // into ARM64 bytes (the x86 core would decode them as garbage and
        // triple-fault). Diverges (halts). The VMLAUNCH below is the unarmed
        // foundation-gate smoke path only.
        if crate::dbt_dispatch::is_armed() {
            dual_puts(b"[x86] Intel armed - host-mode dispatch loop (real kernel)\n");
            let regs = crate::dbt_dispatch::with_global_mut(|s| s.regs);
            run_android_dispatch_loop(regs);
        }

        dual_puts(b"[x86] VMLAUNCH...\n");
        // BLUE flash + 2 beeps removed — fb_fill(FB_BLUE) wipes every line
        // printed above (the JIT map, the EPT root, the translator init).
        // The dual_puts banner directly above now serves the same purpose.
        // VMLAUNCH transfers control: on entry the guest runs (HLT -> VMEXIT);
        // host_rip catches the VMEXIT.  If VMLAUNCH itself fails (e.g. invalid
        // VMCS), CF/ZF are set and execution continues past it — we halt.
        core::arch::asm!(
            "vmlaunch",
            "jmp 2f",
            "2: ",
            options(nostack),
        );
        dual_puts(b"[x86] VMLAUNCH returned - VMCS validation failed.\n");
        const VMCS_VM_INSTR_ERROR: u32 = 0x4400;
        let (err, _ok) = vmread(VMCS_VM_INSTR_ERROR);
        dual_puts(b"[x86] VM_INSTRUCTION_ERROR = ");
        dual_puthex64(err);
        dual_puts(b"\n");
        halt();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AMD: init_svm_foundation -> VMRUN.  VMRUN is round-trip: control returns to
// the instruction after `vmrun` on every VMEXIT, with host state restored from
// HSAVE.  No separate host_rip handler is required.
// ─────────────────────────────────────────────────────────────────────────────

unsafe fn boot_amd(
    vmcb_pa: u64,
    hsave_pa: u64,
    npt_pml4_pa: u64,
    guest_ram_pa: u64,
    kernel_entry_pa: u64,
    extra_region: Option<(u64, u64)>,
) -> ! {
    unsafe {
        dual_puts(b"[x86] AMD path: building NPT identity map...\n");
        build_npt_identity_map(guest_ram_pa);
        // bisect(5/6/7/8/9) removed throughout this function — the
        // dual_puts banners between each step now serve the same purpose
        // as the ascending-pitch tones, with the advantage that the
        // operator can see which stage failed without holding a
        // stopwatch to a wave file.
        if let Some((base, size)) = extra_region {
            dual_puts(b"[x86] NPT 2-MiB map for Android handoff: base=");
            dual_puthex64(base);
            dual_puts(b" size=");
            dual_puthex64(size);
            dual_puts(b"\n");
            build_npt_2mib_range(base, size);
        }
        let guest_cr3 = build_guest_page_table(guest_ram_pa);
        dual_puts(b"[x86] Guest CR3 (PML4)= "); dual_puthex64(guest_cr3); dual_puts(b"\n");
        dual_puts(b"[x86] kernel_entry_pa = "); dual_puthex64(kernel_entry_pa); dual_puts(b"\n");

        let cfg = SvmFoundationConfig {
            vmcb_pa,
            hsave_pa,
            npt_pml4_pa,
            kernel_entry_pa,
            guest_ram_base:  guest_ram_pa,
            // 1 GiB — see matching boot_intel comment for rationale.
            // The Android handoff region (HANDOFF_REGION_SIZE in
            // android_handoff.rs) is what gets NPT-mapped via `extra_region`;
            // this field is what foundation validation + EPT/NPT-violation
            // bounds-checks compare GPAs against.
            guest_ram_size:  1024 * 1024 * 1024,
            mmio_base:       0,
            mmio_size:       0,
            guest_64bit:     true,
        };

        dual_puts(b"[x86] init_svm_foundation()...\n");
        beep_once(1300); // diagnostic: about to call init_svm_foundation
        let vmcb = &mut *(ptr::addr_of_mut!(VMCB_REGION));
        let mut svm_state = match init_svm_foundation(&cfg, vmcb) {
            Ok(state) => {
                dual_puts(b"[x86] init_svm_foundation: phase=");
                dual_puthex64(state.phase as u64);
                dual_puts(b" (NPT active)\n");
                state
            }
            Err(_) => {
                dual_puts(b"[x86] init_svm_foundation FAILED. Check BIOS SVM.\n");
                halt();
            }
        };

        vmcb.write_u64(VMCB_SAVE_CR3, guest_cr3);

        // Publish the active NPT root + VMCB to the W^X subsystem and
        // install the translator's commit_rx_via_ept callback. After this
        // point any aether_dbt_translate_block that emits into the JIT
        // arena will flip the corresponding host PA from RW to RX via the
        // active NPT and arm a TLB_CTL = FLUSH_ALL on the next VMRUN
        // (AMD has no INVNPT — flush executes during VMRUN transition).
        set_active_npt(npt_pml4_pa, vmcb_pa);
        install_dbt_ept_callbacks();
        dual_puts(b"[x86] NPT W^X callback installed (PML4 = ");
        dual_puthex64(npt_pml4_pa);
        dual_puts(b", VMCB = ");
        dual_puthex64(vmcb_pa);
        dual_puts(b")\n");

        // Initialise the translator runtime. Same JIT region as the Intel
        // path — the runtime is single-vCPU regardless of vendor.
        const JIT_CACHE_BASE_PA_AMD: u64 = 0x2_0000_0000;
        const BUMP_ARENA_BASE_PA_AMD: u64 = 0x2_0100_0000;
        const BUMP_ARENA_BYTES_AMD: usize = 1 * 1024 * 1024;
        // Map the JIT cache + bump arena into the active NPT before the
        // translator emits any code. JIT lives at PDPT idx 8 (8 GiB),
        // well above the UEFI 4 GiB identity map, so without this call
        // the first JMP into translated code would nested-page-fault.
        // 32 MiB covers 16 MiB JIT + 1 MiB bump arena with headroom.
        const JIT_NPT_MAP_BYTES_AMD: u64 = 32 * 1024 * 1024;
        build_npt_2mib_jit_range(JIT_CACHE_BASE_PA_AMD, JIT_NPT_MAP_BYTES_AMD);
        dual_puts(b"[x86] NPT JIT region mapped: base=");
        dual_puthex64(JIT_CACHE_BASE_PA_AMD);
        dual_puts(b" size=");
        dual_puthex64(JIT_NPT_MAP_BYTES_AMD);
        dual_puts(b"\n");
        let _ = translator_dbt_init(
            JIT_CACHE_BASE_PA_AMD,
            TRANSLATOR_JIT_BYTES,
            BUMP_ARENA_BASE_PA_AMD,
            BUMP_ARENA_BYTES_AMD,
        );
        dual_puts(b"[x86] translator runtime initialised (JIT = ");
        dual_puthex64(JIT_CACHE_BASE_PA_AMD);
        dual_puts(b")\n");

        // ── M3: host-mode MULTI-BLOCK dispatch loop + memory STORE/LOAD ─────
        // Builds on the silicon-proven M2 single-block CALL. Proves, on real
        // AMD hardware: (1) a translated STORE writes guest memory, (2) a
        // translated LOAD reads it back, (3) a real translate -> run -> read
        // next-pc -> repeat dispatch loop runs multiple basic blocks across a
        // branch. This is the exact loop shape M4 (kernel boot) needs.
        //
        // Install the host IDT first so any fault during a CALL is a readable
        // line, not a triple-fault reset. host_offset bytes live in the low-BSS
        // global-heap Vec (identity-mapped, executable on this firmware per M2).
        crate::host_idt::install_host_idt();

        dual_puts(b"[jit] M3 dispatch: STORE/LOAD + multi-block branch loop\n");

        // pc lives at GuestRegisterFile byte 0x100 => flat slot 32.
        const PC_SLOT: usize = 0x100 / 8;
        const PROG_BASE: u64 = 0x1000;
        const DISPATCH_CAP: u32 = 64; // hard ceiling — cannot infinite-loop

        // Contiguous 24-byte program, two basic blocks (gpr[2] pre-seeded = &OBS):
        //   Block A: 0x1000 MOVZ X0,#0x41 ; 0x1004 STR X0,[X2] ; 0x1008 B +4
        //   Block B: 0x100C LDR X1,[X2]   ; 0x1010 ADD X1,X1,X1 ; 0x1014 B ->0x2000
        // Block A's B targets 0x100C (the next instruction) so block B follows
        // contiguously; the final B targets 0x2000 (outside program -> stop).
        let m3_prog: [u8; 0x18] = [
            0x20, 0x08, 0x80, 0xD2, // 0x1000 MOVZ X0,#0x41
            0x40, 0x00, 0x00, 0xF9, // 0x1004 STR  X0,[X2]
            0x01, 0x00, 0x00, 0x14, // 0x1008 B +4 (-> 0x100C)
            0x41, 0x00, 0x40, 0xF9, // 0x100C LDR  X1,[X2]
            0x21, 0x00, 0x01, 0x8B, // 0x1010 ADD  X1,X1,X1
            0xFB, 0x03, 0x00, 0x14, // 0x1014 B -> 0x2000 (offset +0xFEC)
        ];

        // Seed the register file: zero it, seed the read-only ID system
        // registers (MIDR/MPIDR/CurrentEL/... so MRS returns a real identity),
        // then set X2 = host VA of M3_OBS (STR/LDR base) and pc = base.
        {
            let rf = &mut *core::ptr::addr_of_mut!(M2_REGFILE);
            aether_translator::runtime::context::seed_sysregs(rf);
            rf[2] = core::ptr::addr_of_mut!(M3_OBS) as u64; // X2 -> &M3_OBS
            rf[PC_SLOT] = PROG_BASE;
            *core::ptr::addr_of_mut!(M3_OBS) = 0; // unambiguous store check
        }

        let prog_end = PROG_BASE + m3_prog.len() as u64;
        let mut iters: u32 = 0;
        loop {
            if iters >= DISPATCH_CAP {
                dual_puts(b"[jit] dispatch cap hit -- aborting loop\n");
                break;
            }
            iters += 1;

            // Next pc = whatever the previous block's terminator WritePc'd.
            let pc = (*core::ptr::addr_of!(M2_REGFILE))[PC_SLOT];
            dual_puts(b"[jit] iter pc=");
            dual_puthex64(pc);

            // Normal exit: pc left the program window (final B -> 0x2000).
            if pc < PROG_BASE || pc >= prog_end {
                dual_puts(b" (left program -- done)\n");
                break;
            }

            let off = (pc - PROG_BASE) as usize;
            let slice = &m3_prog[off..];
            let tr = aether_dbt_translate_block(pc, slice);
            if tr != AetherDbtResult::Ok {
                dual_puts(b" translate FAILED rc=");
                dual_puthex64(tr as u64);
                let (fp, fw, fk) = aether_dbt_last_failure();
                dual_puts(b" failpc=");
                dual_puthex64(fp);
                dual_puts(b" word=");
                dual_puthex64(fw as u64);
                dual_puts(b" kind=");
                dual_puthex64(fk as u64);
                dual_puts(b"\n");
                break;
            }
            let (host_va, len) = match aether_dbt_block_host_va(pc) {
                Some(v) => v,
                None => {
                    dual_puts(b" host_va MISS (BUG)\n");
                    break;
                }
            };
            dual_puts(b" host_va=");
            dual_puthex64(host_va as u64);
            dual_puts(b" len=");
            dual_puthex64(len as u64);

            // Structural gate before CALL (shared checker; see
            // block_is_safe_to_enter / dbt::block_bytes_are_safe).
            if !block_is_safe_to_enter(host_va, len) {
                dual_puts(b" UNSAFE -- abort\n");
                break;
            }
            dual_puts(b"\n");

            let rf = core::ptr::addr_of_mut!(M2_REGFILE) as *mut u64;
            enter_host_block(host_va as *const u8, rf);
        }

        // ── Verdict ─────────────────────────────────────────────────────────
        let obs = *core::ptr::addr_of!(M3_OBS);
        let regs = &*core::ptr::addr_of!(M2_REGFILE);
        let (x0, x1) = (regs[0], regs[1]);
        dual_puts(b"[jit] M3 OBS=");
        dual_puthex64(obs);
        dual_puts(b" X0=");
        dual_puthex64(x0);
        dual_puts(b" X1=");
        dual_puthex64(x1);
        dual_puts(b" iters=");
        dual_puthex64(iters as u64);
        dual_puts(b"\n");
        // iters<=4 guards against a degenerate cap-exit (64 iters) passing the
        // idempotent OBS/X0/X1 check: the real program runs exactly 3 iterations
        // (block A, block B, then pc=0x2000 out-of-range break).
        if obs == 0x41 && x0 == 0x41 && x1 == 0x82 && iters <= 4 {
            dual_puts(b"[jit] *** STORE+LOAD+MULTI-BLOCK DISPATCH ON AMD SILICON ***\n");
            beep_once(2000); // triumphant high tone
        } else {
            dual_puts(b"[jit] M3 MISMATCH (want OBS=0x41 X0=0x41 X1=0x82 iters<=4)\n");
            beep_n(2, 600);
        }
        dual_puts(b"[jit] M3 proof complete\n");

        // ── M4a: NZCV + system-register on-silicon proof ───────────────────
        // One block exercising the M4a translator features on real AMD hardware:
        //   sysreg STORE (MSR), sysreg LOAD (MRS), seeded RO read (MRS MPIDR),
        //   flag materialization (CMP -> NZCV at [R15+0x108]), and a conditional
        //   branch that READS that NZCV (B.EQ -> Csel variant 0). All paths the
        //   adversarial review verified correct (no CSINC/CSNEG, no spill).
        //
        //   0x3000 MOVZ X0,#0xABC      X0 = 0xABC
        //   0x3004 MSR  SCTLR_EL1,X0   SCTLR = 0xABC
        //   0x3008 MRS  X1,SCTLR_EL1   X1 = 0xABC   (sysreg round-trip)
        //   0x300C MRS  X2,MPIDR_EL1   X2 = 0x80000000 (seeded RO id reg)
        //   0x3010 MOVZ X3,#7          X3 = 7
        //   0x3014 MOVZ X4,#7          X4 = 7
        //   0x3018 CMP  X3,X4          NZCV: Z=1 (equal)
        //   0x301C B.EQ +8             Z=1 -> taken -> pc = 0x3024
        const M4A_PC: u64 = 0x3000;
        let m4a_prog: [u8; 0x20] = [
            0x80, 0x57, 0x81, 0xD2, // MOVZ X0,#0xABC
            0x00, 0x10, 0x18, 0xD5, // MSR  SCTLR_EL1, X0
            0x01, 0x10, 0x38, 0xD5, // MRS  X1, SCTLR_EL1
            0xA2, 0x00, 0x38, 0xD5, // MRS  X2, MPIDR_EL1
            0xE3, 0x00, 0x80, 0xD2, // MOVZ X3,#7
            0xE4, 0x00, 0x80, 0xD2, // MOVZ X4,#7
            0x7F, 0x00, 0x04, 0xEB, // CMP  X3,X4 (SUBS XZR,X3,X4)
            0x40, 0x00, 0x00, 0x54, // B.EQ +8 (-> 0x3024)
        ];
        dual_puts(b"[jit] M4a proof: MSR/MRS SCTLR + MRS MPIDR + CMP/B.EQ\n");
        {
            // Re-seed the RO ID regs (M3 left them intact, but be explicit) and
            // set the entry pc; GPR state is irrelevant (block sets X0-X4).
            let rf = &mut *core::ptr::addr_of_mut!(M2_REGFILE);
            aether_translator::runtime::context::seed_sysregs(rf);
            rf[PC_SLOT] = M4A_PC;
        }
        let m4a_ok = {
            let tr = aether_dbt_translate_block(M4A_PC, &m4a_prog);
            if tr != AetherDbtResult::Ok {
                dual_puts(b"[jit] M4a translate FAILED rc=");
                dual_puthex64(tr as u64);
                dual_puts(b"\n");
                false
            } else if let Some((host_va, len)) = aether_dbt_block_host_va(M4A_PC) {
                if !block_is_safe_to_enter(host_va, len) {
                    dual_puts(b"[jit] M4a block UNSAFE -- skipping CALL\n");
                    false
                } else {
                    let rf = core::ptr::addr_of_mut!(M2_REGFILE) as *mut u64;
                    enter_host_block(host_va as *const u8, rf);
                    let regs = &*core::ptr::addr_of!(M2_REGFILE);
                    let (x1m, x2m, pcm) = (regs[1], regs[2], regs[PC_SLOT]);
                    dual_puts(b"[jit] M4a X1(SCTLR)=");
                    dual_puthex64(x1m);
                    dual_puts(b" X2(MPIDR)=");
                    dual_puthex64(x2m);
                    dual_puts(b" pc(B.EQ)=");
                    dual_puthex64(pcm);
                    dual_puts(b"\n");
                    x1m == 0xABC && x2m == 0x8000_0000 && pcm == 0x3024
                }
            } else {
                dual_puts(b"[jit] M4a host_va MISS (BUG)\n");
                false
            }
        };
        if m4a_ok {
            dual_puts(b"[jit] *** NZCV + SYSREG ON AMD SILICON ***\n");
            beep_once(2400); // distinct high tone for the M4a proof
        } else {
            dual_puts(b"[jit] M4a MISMATCH (want X1=0xABC X2=0x80000000 pc=0x3024)\n");
            beep_n(2, 500);
        }
        // ── end M4a ─────────────────────────────────────────────────────────

        // ── M4b-1: carry-in + branched CCMP on-silicon proof ────────────────
        // Two blocks exercising the M4b-1 translator features on real AMD
        // hardware. Both decode->lift->lower->execute paths were host-verified
        // in tests/at_exec_proof.rs (m4b_adcs_carry_chain / m4b_ccmp_branched);
        // this runs the identical byte programs through the live dispatch path.
        //
        // Block A — ADCS carry-in (a 128-bit add):
        //   0x4000 MOVN X2,#0        X2 = 0xFFFF_FFFF_FFFF_FFFF
        //   0x4004 MOVZ X4,#1
        //   0x4008 MOVZ X3,#0
        //   0x400C MOVZ X5,#0
        //   0x4010 ADDS X0,X2,X4     X0 = 0, C = 1
        //   0x4014 ADCS X1,X3,X5     X1 = 0 + 0 + carry = 1
        const M4B1A_PC: u64 = 0x4000;
        let m4b1a_prog: [u8; 0x18] = [
            0x02, 0x00, 0x80, 0x92, // MOVN X2,#0
            0x24, 0x00, 0x80, 0xD2, // MOVZ X4,#1
            0x03, 0x00, 0x80, 0xD2, // MOVZ X3,#0
            0x05, 0x00, 0x80, 0xD2, // MOVZ X5,#0
            0x40, 0x00, 0x04, 0xAB, // ADDS X0,X2,X4
            0x61, 0x00, 0x05, 0xBA, // ADCS X1,X3,X5
        ];
        dual_puts(b"[jit] M4b-1 proof A: ADDS/ADCS 128-bit carry chain\n");
        {
            let rf = &mut *core::ptr::addr_of_mut!(M2_REGFILE);
            aether_translator::runtime::context::seed_sysregs(rf);
            rf[PC_SLOT] = M4B1A_PC;
        }
        let m4b1a_ok = {
            let tr = aether_dbt_translate_block(M4B1A_PC, &m4b1a_prog);
            if tr != AetherDbtResult::Ok {
                dual_puts(b"[jit] M4b-1A translate FAILED rc=");
                dual_puthex64(tr as u64);
                dual_puts(b"\n");
                false
            } else if let Some((host_va, len)) = aether_dbt_block_host_va(M4B1A_PC) {
                if !block_is_safe_to_enter(host_va, len) {
                    dual_puts(b"[jit] M4b-1A block UNSAFE -- skipping CALL\n");
                    false
                } else {
                    let rf = core::ptr::addr_of_mut!(M2_REGFILE) as *mut u64;
                    enter_host_block(host_va as *const u8, rf);
                    let regs = &*core::ptr::addr_of!(M2_REGFILE);
                    let (x0, x1) = (regs[0], regs[1]);
                    dual_puts(b"[jit] M4b-1A X0(lo)=");
                    dual_puthex64(x0);
                    dual_puts(b" X1(hi)=");
                    dual_puthex64(x1);
                    dual_puts(b"\n");
                    x0 == 0 && x1 == 1
                }
            } else {
                dual_puts(b"[jit] M4b-1A host_va MISS (BUG)\n");
                false
            }
        };

        // Block B — branched CCMP:
        //   0x5000 MOVZ X0,#5
        //   0x5004 MOVZ X1,#5
        //   0x5008 MOVZ X2,#7
        //   0x500C MOVZ X3,#7
        //   0x5010 CMP  X0,X1          X0==X1 -> EQ holds
        //   0x5014 CCMP X2,X3,#0,EQ    EQ -> NZCV = cmp(X2,X3) -> Z=1 (7==7)
        // NZCV lives at [R15+0x108] -> regfile slot 33; Z is bit 30.
        const M4B1B_PC: u64 = 0x5000;
        const NZCV_SLOT: usize = 33;
        let m4b1b_prog: [u8; 0x18] = [
            0xA0, 0x00, 0x80, 0xD2, // MOVZ X0,#5
            0xA1, 0x00, 0x80, 0xD2, // MOVZ X1,#5
            0xE2, 0x00, 0x80, 0xD2, // MOVZ X2,#7
            0xE3, 0x00, 0x80, 0xD2, // MOVZ X3,#7
            0x1F, 0x00, 0x01, 0xEB, // CMP  X0,X1
            0x40, 0x00, 0x43, 0xFA, // CCMP X2,X3,#0,EQ
        ];
        dual_puts(b"[jit] M4b-1 proof B: CMP + CCMP X2,X3,#0,EQ\n");
        {
            let rf = &mut *core::ptr::addr_of_mut!(M2_REGFILE);
            aether_translator::runtime::context::seed_sysregs(rf);
            rf[PC_SLOT] = M4B1B_PC;
        }
        let m4b1b_ok = {
            let tr = aether_dbt_translate_block(M4B1B_PC, &m4b1b_prog);
            if tr != AetherDbtResult::Ok {
                dual_puts(b"[jit] M4b-1B translate FAILED rc=");
                dual_puthex64(tr as u64);
                dual_puts(b"\n");
                false
            } else if let Some((host_va, len)) = aether_dbt_block_host_va(M4B1B_PC) {
                if !block_is_safe_to_enter(host_va, len) {
                    dual_puts(b"[jit] M4b-1B block UNSAFE -- skipping CALL\n");
                    false
                } else {
                    let rf = core::ptr::addr_of_mut!(M2_REGFILE) as *mut u64;
                    enter_host_block(host_va as *const u8, rf);
                    let regs = &*core::ptr::addr_of!(M2_REGFILE);
                    let nzcv = regs[NZCV_SLOT];
                    dual_puts(b"[jit] M4b-1B NZCV=");
                    dual_puthex64(nzcv);
                    dual_puts(b" Z=");
                    dual_puthex64(((nzcv >> 30) & 1) as u64);
                    dual_puts(b"\n");
                    (nzcv & (1 << 30)) != 0
                }
            } else {
                dual_puts(b"[jit] M4b-1B host_va MISS (BUG)\n");
                false
            }
        };

        // Block C — SBCS borrow chain (the must-fix-1 path: CF seeded as the
        // BORROW !C via BT+CMC, not ARM C). 128-bit (X3:X2)-(X5:X4) =
        // (1:0)-(0:1) = 2^64-1 -> X0 = 0xFFFF_FFFF_FFFF_FFFF, X1 = 0. The
        // pre-fix code (no CMC) produced X1 = 1 (bit-exact inverse).
        //   0x6000 MOVZ X2,#0
        //   0x6004 MOVZ X4,#1
        //   0x6008 MOVZ X3,#1
        //   0x600C MOVZ X5,#0
        //   0x6010 SUBS X0,X2,X4   X0 = ~0, borrow -> ARM C = 0
        //   0x6014 SBCS X1,X3,X5   X1 = 1 - 0 - borrow(1) = 0
        const M4B1C_PC: u64 = 0x6000;
        let m4b1c_prog: [u8; 0x18] = [
            0x02, 0x00, 0x80, 0xD2, // MOVZ X2,#0
            0x24, 0x00, 0x80, 0xD2, // MOVZ X4,#1
            0x23, 0x00, 0x80, 0xD2, // MOVZ X3,#1
            0x05, 0x00, 0x80, 0xD2, // MOVZ X5,#0
            0x40, 0x00, 0x04, 0xEB, // SUBS X0,X2,X4
            0x61, 0x00, 0x05, 0xFA, // SBCS X1,X3,X5
        ];
        dual_puts(b"[jit] M4b-1 proof C: SUBS/SBCS 128-bit borrow chain\n");
        {
            let rf = &mut *core::ptr::addr_of_mut!(M2_REGFILE);
            aether_translator::runtime::context::seed_sysregs(rf);
            rf[PC_SLOT] = M4B1C_PC;
        }
        let m4b1c_ok = {
            let tr = aether_dbt_translate_block(M4B1C_PC, &m4b1c_prog);
            if tr != AetherDbtResult::Ok {
                dual_puts(b"[jit] M4b-1C translate FAILED rc=");
                dual_puthex64(tr as u64);
                dual_puts(b"\n");
                false
            } else if let Some((host_va, len)) = aether_dbt_block_host_va(M4B1C_PC) {
                if !block_is_safe_to_enter(host_va, len) {
                    dual_puts(b"[jit] M4b-1C block UNSAFE -- skipping CALL\n");
                    false
                } else {
                    let rf = core::ptr::addr_of_mut!(M2_REGFILE) as *mut u64;
                    enter_host_block(host_va as *const u8, rf);
                    let regs = &*core::ptr::addr_of!(M2_REGFILE);
                    let (x0, x1) = (regs[0], regs[1]);
                    dual_puts(b"[jit] M4b-1C X0(lo)=");
                    dual_puthex64(x0);
                    dual_puts(b" X1(hi)=");
                    dual_puthex64(x1);
                    dual_puts(b"\n");
                    x0 == 0xFFFF_FFFF_FFFF_FFFF && x1 == 0
                }
            } else {
                dual_puts(b"[jit] M4b-1C host_va MISS (BUG)\n");
                false
            }
        };

        // Block D — CCMN ADD polarity (the must-fix-2 path). CCMN X0,X1,#0,AL
        // with X0=1,X1=1 sets flags from 1+1=2 -> Z=0. The pre-fix code lowered
        // CCMN as CCMP (1-1=0 -> Z=1).
        //   0x7000 MOVZ X0,#1
        //   0x7004 MOVZ X1,#1
        //   0x7008 CCMN X0,X1,#0,AL    NZCV = flags(1+1) -> Z = 0
        const M4B1D_PC: u64 = 0x7000;
        let m4b1d_prog: [u8; 0x0C] = [
            0x20, 0x00, 0x80, 0xD2, // MOVZ X0,#1
            0x21, 0x00, 0x80, 0xD2, // MOVZ X1,#1
            0x00, 0xE0, 0x41, 0xBA, // CCMN X0,X1,#0,AL
        ];
        dual_puts(b"[jit] M4b-1 proof D: CCMN X0,X1,#0,AL (ADD polarity)\n");
        {
            let rf = &mut *core::ptr::addr_of_mut!(M2_REGFILE);
            aether_translator::runtime::context::seed_sysregs(rf);
            rf[PC_SLOT] = M4B1D_PC;
        }
        let m4b1d_ok = {
            let tr = aether_dbt_translate_block(M4B1D_PC, &m4b1d_prog);
            if tr != AetherDbtResult::Ok {
                dual_puts(b"[jit] M4b-1D translate FAILED rc=");
                dual_puthex64(tr as u64);
                dual_puts(b"\n");
                false
            } else if let Some((host_va, len)) = aether_dbt_block_host_va(M4B1D_PC) {
                if !block_is_safe_to_enter(host_va, len) {
                    dual_puts(b"[jit] M4b-1D block UNSAFE -- skipping CALL\n");
                    false
                } else {
                    let rf = core::ptr::addr_of_mut!(M2_REGFILE) as *mut u64;
                    enter_host_block(host_va as *const u8, rf);
                    let regs = &*core::ptr::addr_of!(M2_REGFILE);
                    let nzcv = regs[NZCV_SLOT];
                    dual_puts(b"[jit] M4b-1D NZCV=");
                    dual_puthex64(nzcv);
                    dual_puts(b" Z=");
                    dual_puthex64(((nzcv >> 30) & 1) as u64);
                    dual_puts(b"\n");
                    // ADD polarity: 1+1=2 non-zero -> Z clear.
                    (nzcv & (1 << 30)) == 0
                }
            } else {
                dual_puts(b"[jit] M4b-1D host_va MISS (BUG)\n");
                false
            }
        };

        if m4b1a_ok && m4b1b_ok && m4b1c_ok && m4b1d_ok {
            dual_puts(b"[jit] *** ADCS/SBCS CARRY + CCMP/CCMN ON AMD SILICON ***\n");
            beep_once(2700); // distinct top tone for the M4b-1 proof
        } else {
            dual_puts(b"[jit] M4b-1 MISMATCH (A:X0=0,X1=1 B:Z=1 C:X0=~0,X1=0 D:Z=0)\n");
            beep_n(3, 400);
        }
        // ── end M4b-1 ───────────────────────────────────────────────────────

        // ── M4b-2: synthetic __enable_mmu on-silicon proof ──────────────────
        // THE headline software-MMU gate. A small ARM64 program builds-then-
        // enables the MMU and loads through a VIRTUAL address — proving the
        // translated load WALKED the guest page tables (host-mirrored in
        // tests/at_exec_proof.rs::m4b2_synthetic_enable_mmu_then_load).
        //
        // The page tables are pre-built HERE in Rust inside M4B2_PT_SCRATCH (5
        // pages: L0/L1/L2/L3/data), the MMU window is pinned to that scratch for
        // the proof, and the translated block does the genuine __enable_mmu
        // sequence ITSELF:
        //   0xC000 MSR TTBR0_EL1, X0   X0 = L0 base   (flush soft TLB + JIT cache)
        //   0xC004 MSR TCR_EL1,   X1   X1 = T0SZ=16   (flush …)
        //   0xC008 MSR MAIR_EL1,  X2   X2 = MAIR      (flush …)
        //   0xC00C MSR SCTLR_EL1, X3   X3 = M=1       (no flush — M read live)
        //   0xC010 ISB                 serialise      (→ x86 CPUID)
        //   0xC014 LDR X5, [X4]        X4 = mapped VA → walked to the data page
        // Expect X5 == the seeded data word. A second block loads an UNMAPPED VA
        // and must record a pending Data Abort (PEND_PENDING==1).
        const M4B2_PC: u64 = 0xC000;
        const M4B2_FAULT_PC: u64 = 0xC100;
        // Mapped VA (low/TTBR0 half, 4 KiB-aligned) and the data word the
        // post-__enable_mmu load must read back.
        const M4B2_VA: u64 = 0x0000_1234_ABCD_E000;
        const M4B2_UNMAPPED_VA: u64 = 0x0000_0033_0000_0000;
        const M4B2_DATA_WORD: u64 = 0xFEED_FACE_C0DE_0042;
        const M4B2_MAIR_VALUE: u64 = 0x0000_0000_0000_00FF; // Normal WB @ idx0
        const M4B2_SCTLR_MMU_ON: u64 = (1 << 0) | (1 << 2) | (1 << 12); // M|C|I
        // Descriptor helpers (same encoding as the walker's tests).
        const ADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000;
        // Program 1: MSR TTBR0,X0 ; MSR TCR,X1 ; MSR MAIR,X2 ; MSR SCTLR,X3 ; ISB ;
        //            LDR X5,[X4].   (encodings recomputed; MSR SCTLR_EL1,X0 ==
        //            0xD5181000 is the known-good M4a word, so the family checks.)
        let m4b2_prog: [u8; 0x18] = [
            0x00, 0x20, 0x18, 0xD5, // MSR TTBR0_EL1, X0  (0xD5182000)
            0x41, 0x20, 0x18, 0xD5, // MSR TCR_EL1,   X1  (0xD5182041)
            0x02, 0xA2, 0x18, 0xD5, // MSR MAIR_EL1,  X2  (0xD518A202)
            0x03, 0x10, 0x18, 0xD5, // MSR SCTLR_EL1, X3  (0xD5181003)
            0xDF, 0x3F, 0x03, 0xD5, // ISB               (0xD5033FDF)
            0x85, 0x00, 0x40, 0xF9, // LDR X5, [X4]      (0xF9400085)
        ];
        // Program 2 (fault): TTBR0 from X6 / TCR from X7 so neither aliases the
        // load base (X0=unmapped VA) or dest (X5):
        //   MSR TTBR0,X6 ; MSR TCR,X7 ; MSR MAIR,X2 ; MSR SCTLR,X3 ; ISB ; LDR X5,[X0]
        let m4b2_fault_prog: [u8; 0x18] = [
            0x06, 0x20, 0x18, 0xD5, // MSR TTBR0_EL1, X6  (0xD5182006)
            0x47, 0x20, 0x18, 0xD5, // MSR TCR_EL1,   X7  (0xD5182047)
            0x02, 0xA2, 0x18, 0xD5, // MSR MAIR_EL1,  X2  (0xD518A202)
            0x03, 0x10, 0x18, 0xD5, // MSR SCTLR_EL1, X3  (0xD5181003)
            0xDF, 0x3F, 0x03, 0xD5, // ISB               (0xD5033FDF)
            0x05, 0x00, 0x40, 0xF9, // LDR X5, [X0]      (0xF9400005)
        ];

        // Build the 4-level tables in M4B2_PT_SCRATCH (page0=L0 … page3=L3,
        // page4=data) and pin the MMU window to it. The scratch's host address
        // doubles as the "guest PA" (identity invariant), so the walker reads the
        // descriptors directly. SAFETY: single-core EL2; exclusive access to the
        // static for the proof's duration.
        let (m4b2_l0, m4b2_data_pa) = {
            let base = core::ptr::addr_of_mut!(M4B2_PT_SCRATCH) as u64;
            let l0 = base;
            let l1 = base + 4096;
            let l2 = base + 8192;
            let l3 = base + 12288;
            let data = base + 16384;
            let put = |pa: u64, idx: usize, val: u64| {
                // SAFETY: in-scratch 4 KiB page; idx < 512.
                unsafe { core::ptr::write_volatile((pa as *mut u64).add(idx), val) };
            };
            let table_desc = |next: u64| (next & ADDR_MASK) | 0b11; // valid + table
            let leaf = |oa: u64| (oa & ADDR_MASK) | 0b11 | (1 << 10); // valid+page+AF
            put(l0, ((M4B2_VA >> 39) & 0x1FF) as usize, table_desc(l1));
            put(l1, ((M4B2_VA >> 30) & 0x1FF) as usize, table_desc(l2));
            put(l2, ((M4B2_VA >> 21) & 0x1FF) as usize, table_desc(l3));
            put(l3, ((M4B2_VA >> 12) & 0x1FF) as usize, leaf(data));
            // Seed the data word the walked load must read back.
            put(data, 0, M4B2_DATA_WORD);
            // Pin the software-MMU window to exactly this 5-page scratch.
            aether_translator::runtime::mmu::aether_mmu_set_window(base, 5 * 4096);
            aether_translator::runtime::mmu::aether_mmu_flush_all();
            (l0, data)
        };
        dual_puts(b"[jit] M4b-2 proof: synthetic __enable_mmu (build tables, MMU on, LDR VA)\n");
        dual_puts(b"[mmu] proof window base=");
        dual_puthex64(m4b2_l0);
        dual_puts(b" data_pa=");
        dual_puthex64(m4b2_data_pa);
        dual_puts(b"\n");

        // Block 1: enable the MMU and load through the mapped VA.
        {
            let rf = &mut *core::ptr::addr_of_mut!(M2_REGFILE);
            aether_translator::runtime::context::seed_sysregs(rf);
            rf[PC_SLOT] = M4B2_PC;
            rf[0] = m4b2_l0; // X0 → TTBR0_EL1
            rf[1] = 16; // X1 → TCR_EL1: T0SZ=16 (48-bit VA, 4-level)
            rf[2] = M4B2_MAIR_VALUE; // X2 → MAIR_EL1
            rf[3] = M4B2_SCTLR_MMU_ON; // X3 → SCTLR_EL1 (M=1)
            rf[4] = M4B2_VA; // X4 = mapped VA to load from
            rf[5] = 0; // X5 = LDR dest (must become the data word)
        }
        let m4b2_load = {
            let tr = aether_dbt_translate_block(M4B2_PC, &m4b2_prog);
            if tr != AetherDbtResult::Ok {
                dual_puts(b"[jit] M4b-2 translate FAILED rc=");
                dual_puthex64(tr as u64);
                dual_puts(b"\n");
                0u64
            } else if let Some((host_va, len)) = aether_dbt_block_host_va(M4B2_PC) {
                if !block_is_safe_to_enter(host_va, len) {
                    dual_puts(b"[jit] M4b-2 block UNSAFE -- skipping CALL\n");
                    0u64
                } else {
                    let rf = core::ptr::addr_of_mut!(M2_REGFILE) as *mut u64;
                    enter_host_block(host_va as *const u8, rf);
                    (*core::ptr::addr_of!(M2_REGFILE))[5] // X5 = loaded value
                }
            } else {
                dual_puts(b"[jit] M4b-2 host_va MISS (BUG)\n");
                0u64
            }
        };
        // Print the headline line the user watches for on the Ryzen.
        dual_puts(b"[jit] M4b-2 MMU-ON LDR=");
        dual_puthex64(m4b2_load);
        dual_puts(b" (expect ");
        dual_puthex64(M4B2_DATA_WORD);
        dual_puts(b")\n");

        // Block 2: the fault mirror — load an UNMAPPED VA after enabling the MMU;
        // the walker must record a pending Data Abort (PEND_PENDING==1).
        {
            let rf = &mut *core::ptr::addr_of_mut!(M2_REGFILE);
            aether_translator::runtime::context::seed_sysregs(rf);
            rf[PC_SLOT] = M4B2_FAULT_PC;
            rf[6] = m4b2_l0; // X6 → TTBR0_EL1 (real base, kept off the load operands)
            rf[7] = 16; // X7 → TCR_EL1
            rf[2] = M4B2_MAIR_VALUE; // X2 → MAIR_EL1
            rf[3] = M4B2_SCTLR_MMU_ON; // X3 → SCTLR_EL1 (M=1)
            rf[0] = M4B2_UNMAPPED_VA; // X0 = unmapped VA (load base)
            rf[5] = 0xDEAD_DEAD_DEAD_DEAD; // X5 = dest sentinel (must survive)
        }
        let m4b2_fault_pend = {
            let tr = aether_dbt_translate_block(M4B2_FAULT_PC, &m4b2_fault_prog);
            if tr != AetherDbtResult::Ok {
                dual_puts(b"[jit] M4b-2 fault translate FAILED rc=");
                dual_puthex64(tr as u64);
                dual_puts(b"\n");
                0u64
            } else if let Some((host_va, len)) = aether_dbt_block_host_va(M4B2_FAULT_PC) {
                if !block_is_safe_to_enter(host_va, len) {
                    dual_puts(b"[jit] M4b-2 fault block UNSAFE -- skipping CALL\n");
                    0u64
                } else {
                    let rf = core::ptr::addr_of_mut!(M2_REGFILE) as *mut u64;
                    enter_host_block(host_va as *const u8, rf);
                    let regs = &*core::ptr::addr_of!(M2_REGFILE);
                    use aether_translator::runtime::context::SYSREG_SLOT0;
                    use aether_translator::runtime::mmu::SLOT_PEND_PENDING;
                    regs[SYSREG_SLOT0 + SLOT_PEND_PENDING]
                }
            } else {
                dual_puts(b"[jit] M4b-2 fault host_va MISS (BUG)\n");
                0u64
            }
        };
        dual_puts(b"[jit] M4b-2 unmapped-VA PEND_PENDING=");
        dual_puthex64(m4b2_fault_pend);
        dual_puts(b" (expect 1)\n");

        // Gate the banner on BOTH halves: the mapped load returned the seeded word
        // AND the unmapped load set the pending-fault flag.
        if m4b2_load == M4B2_DATA_WORD && m4b2_fault_pend == 1 {
            dual_puts(b"[jit] *** SOFTWARE MMU WALK ON AMD SILICON ***\n");
            beep_once(3000); // distinct top tone for the M4b-2 headline gate
        } else {
            dual_puts(b"[jit] M4b-2 MISMATCH (want LDR=0xFEEDFACEC0DE0042 PEND=1)\n");
            beep_n(4, 350);
        }
        // ── end M4b-2 ───────────────────────────────────────────────────────

        // ── M4b-6: NEON 3-same vector execute proof (this session's SIMD work) ─
        // ADD V2.4s, V0.4s, V1.4s through the FULL pipeline:
        //   decode(SimdThreeSame) -> lift(VecBin::Add) -> lower_simd_ctx
        //   (movdqu VS0,[R15+vec_disp(0)]; paddd VS0,[R15+vec_disp(1)];
        //    movdqu [R15+vec_disp(2)],VS0) -> EXECUTE on real x86.
        // Host unit tests only assert emitted BYTES; this is the first proof the
        // vector lowering actually RUNS correctly. Context-relative vector stores
        // are the same [R15+disp] path M4a's sysreg writes already validated.
        //   q0 = [1,2,3,4]  q1 = [10,20,30,40]  ->  q2 = [11,22,33,44]
        const M4B6_PC: u64 = 0x5000;
        const VEC_SLOT0: usize = 0x128 / 8; // u64 index of vec[0].lo in regfile
        let m4b6_prog: [u8; 8] = [
            0x02, 0x84, 0xA1, 0x4E, // ADD V2.4s, V0.4s, V1.4s
            0x01, 0x00, 0x00, 0x14, // B +4 (-> 0x5008, out of program: terminator)
        ];
        {
            let rf = &mut *core::ptr::addr_of_mut!(M2_REGFILE);
            aether_translator::runtime::context::seed_sysregs(rf);
            rf[PC_SLOT] = M4B6_PC;
            rf[VEC_SLOT0]     = 0x0000_0002_0000_0001; // q0 lanes 0,1 = 1,2
            rf[VEC_SLOT0 + 1] = 0x0000_0004_0000_0003; // q0 lanes 2,3 = 3,4
            rf[VEC_SLOT0 + 2] = 0x0000_0014_0000_000A; // q1 lanes 0,1 = 10,20
            rf[VEC_SLOT0 + 3] = 0x0000_0028_0000_001E; // q1 lanes 2,3 = 30,40
            rf[VEC_SLOT0 + 4] = 0; // q2 lo (dest cleared)
            rf[VEC_SLOT0 + 5] = 0; // q2 hi
        }
        let m4b6_ok = {
            let tr = aether_dbt_translate_block(M4B6_PC, &m4b6_prog);
            if tr != AetherDbtResult::Ok {
                dual_puts(b"[jit] M4b-6 translate FAILED rc=");
                dual_puthex64(tr as u64);
                let (fp, fw, fk) = aether_dbt_last_failure();
                dual_puts(b" failpc=");
                dual_puthex64(fp);
                dual_puts(b" word=");
                dual_puthex64(fw as u64);
                dual_puts(b" kind=");
                dual_puthex64(fk as u64);
                dual_puts(b"\n");
                false
            } else if let Some((host_va, len)) = aether_dbt_block_host_va(M4B6_PC) {
                if !block_is_safe_to_enter(host_va, len) {
                    dual_puts(b"[jit] M4b-6 block UNSAFE -- skipping CALL\n");
                    false
                } else {
                    let rf = core::ptr::addr_of_mut!(M2_REGFILE) as *mut u64;
                    enter_host_block(host_va as *const u8, rf);
                    let regs = &*core::ptr::addr_of!(M2_REGFILE);
                    let (q2lo, q2hi) = (regs[VEC_SLOT0 + 4], regs[VEC_SLOT0 + 5]);
                    dual_puts(b"[jit] M4b-6 q2.lo=");
                    dual_puthex64(q2lo);
                    dual_puts(b" q2.hi=");
                    dual_puthex64(q2hi);
                    dual_puts(b"\n");
                    q2lo == 0x0000_0016_0000_000B && q2hi == 0x0000_002C_0000_0021
                }
            } else {
                dual_puts(b"[jit] M4b-6 host_va MISS (BUG)\n");
                false
            }
        };
        if m4b6_ok {
            dual_puts(b"[jit] *** NEON 3-SAME VECTOR ADD ON AMD SILICON (M4b-6) ***\n");
            beep_once(2800); // distinct tone for the SIMD proof
        } else {
            dual_puts(b"[jit] M4b-6 MISMATCH (want q2.lo=0x000000160000000B q2.hi=0x0000002C00000021)\n");
            beep_n(3, 450);
        }
        // ── end M4b-6 ───────────────────────────────────────────────────────

        dual_puts(b"[jit] M3+M4a+M4b-1+M4b-2+M4b-6 proofs complete -- entering live dispatch.\n");
        // ── end M3 ──────────────────────────────────────────────────────────

        // M4b-2-bootwire: the premature halt() that used to live here (which
        // parked the CPU right after the M4b-1 proof) is gone. Control now
        // falls through into the real VMRUN dispatch loop below, which routes
        // every instruction-fetch NPF through svm::handle_vm_exit's translator
        // path (translate -> safe -> enter host block -> advance PC).
        //
        // Pin the software MMU's guest physical window to the exact handoff
        // span BEFORE the first dispatch. The walker confines every page-table
        // base + leaf output to this window (No-Boundary). Use the REAL runtime
        // span (dispatch_window() == h.region_pa/size set at arm time), NOT the
        // STAGED_BOOT_IMG_PA constant — on the UEFI-alloc path the kernel lives
        // near 4 GiB and a constant window would reject the first fetch.
        let (win_base, win_size) = dispatch_window();
        aether_translator::runtime::mmu::aether_mmu_set_window(win_base, win_size);
        dual_puts(b"[mmu] guest PA window pinned: base=");
        dual_puthex64(win_base);
        dual_puts(b" size=");
        dual_puthex64(win_size);
        dual_puts(b"\n");
        if crate::dbt_dispatch::is_armed() {
            dual_puts(b"[x86] dispatch armed (handoff staged) - host-mode dispatch loop\n");
            // M4b-5: a real kernel runs through the vendor-neutral HOST-MODE
            // dispatch loop (translate each block + host-CALL it), NOT VMRUN
            // into raw ARM64 (which the x86 core decodes as garbage and
            // triple-faults → SVM SHUTDOWN 0x7F). Diverges (halts).
            let regs = crate::dbt_dispatch::with_global_mut(|s| s.regs);
            run_android_dispatch_loop(regs);
        }
        dual_puts(b"[x86] dispatch NOT armed (no handoff) - VMRUN smoke path\n");

        // Phase 5b: AMD VMRUN is round-trip — control returns here on every
        // VMEXIT with host state restored from HSAVE. Loop: classify exit,
        // emulate (MMIO etc.), VMRUN again on Reenter. Break on Halt.
        //
        // The loop body deliberately re-reads VMCB fields after every VMRUN
        // because emulation may have updated them (e.g. EXITINFO2 for NPF).
        dual_puts(b"[x86] VMRUN dispatch loop start\n");
        beep_once(1500); // diagnostic: about to enter VMRUN loop (last stage)
        // BLUE flash + 2 beeps removed — fb_fill(FB_BLUE) wipes every line
        // printed above. The "VMRUN dispatch loop start" banner now serves
        // the same role visibly on the framebuffer.
        const MAX_VMRUN_ITERATIONS: u64 = 1_000_000;
        let mut iter: u64 = 0;
        loop {
            vmrun(vmcb_pa);
            iter += 1;

            let exit_code = vmcb.exit_code();
            let exit_info_1 = vmcb.read_u64(VMCB_EXIT_INFO_1);
            let exit_info_2 = vmcb.read_u64(VMCB_EXIT_INFO_2);

            // Decide whether to drive the FEX dispatch path or just log.
            if !crate::dbt_dispatch::is_armed() {
                // Foundation gate / single-exit smoke-test behaviour.
                dual_puts(b"[x86] VMCB exit_code = ");
                dual_puthex64(exit_code);
                if exit_code == crate::svm::SVM_EXIT_HLT {
                    dual_puts(b" HLT\n");
                } else if exit_code == 0x400 {
                    dual_puts(b" NPF\n");
                } else {
                    dual_puts(b"\n");
                }
                dual_puts(b"[x86] EXITINFO1 = "); dual_puthex64(exit_info_1); dual_puts(b"\n");
                dual_puts(b"[x86] EXITINFO2 = "); dual_puthex64(exit_info_2); dual_puts(b"\n");
                break;
            }

            // Armed: route through svm::handle_vm_exit, which has the
            // real ARM64 → x86 translator wiring (npt_read_guest_window
            // → aether_dbt_translate_block → commit_rx_via_ept). The
            // older dbt_dispatch::handle_vmexit path uses a DUMMY_RET
            // adapter and never actually translates guest bytes — audit
            // §5b. Wire to the real path so the first NPF on an
            // un-translated instruction fetch invokes the lifter and
            // emits "[dbt] TranslateFail pc=… word=…" instead of
            // silently halting.
            //
            // Print exit_code + EXITINFO unconditionally on first ~16
            // iterations so the post-mortem photo always shows the
            // last-seen exit even if dispatch immediately halts.
            if iter <= 16 {
                dual_puts(b"[vmexit] iter=");
                dual_puthex64(iter);
                dual_puts(b" code=");
                dual_puthex64(exit_code);
                dual_puts(b" info1=");
                dual_puthex64(exit_info_1);
                dual_puts(b" info2=");
                dual_puthex64(exit_info_2);
                dual_puts(b"\n");
            }

            let action = crate::svm::handle_vm_exit(vmcb, &mut svm_state);
            match action {
                crate::svm::SvmExitAction::Resume
                | crate::svm::SvmExitAction::HltHandled => {
                    if iter % 65536 == 0 {
                        dual_puts(b"[fex] dispatch iter=");
                        dual_puthex64(iter);
                        dual_puts(b"\n");
                    }
                    if iter >= MAX_VMRUN_ITERATIONS {
                        dual_puts(b"[fex] iteration cap reached - halting\n");
                        break;
                    }
                    continue;
                }
                crate::svm::SvmExitAction::Terminate => {
                    dual_puts(b"[svm] handle_vm_exit -> Terminate (exit_code=");
                    dual_puthex64(exit_code);
                    dual_puts(b" info1=");
                    dual_puthex64(exit_info_1);
                    dual_puts(b" info2=");
                    dual_puthex64(exit_info_2);
                    dual_puts(b")\n");
                    break;
                }
            }
        }

        dual_puts(b"[x86] Hypervisor in SVM host mode. Halting.\n");
        halt();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// M2 — host-mode JIT execution proof support.
//
// M2_REGFILE is the register file the translated block reads/writes via
// [R15+disp]. It is a flat [u64; 0x328/8] (101 slots) — layout-identical to
// aether_translator::runtime::GuestRegisterFile (repr(C), gpr[] first at
// offset 0, so gpr[0] is slot 0 and gpr[1] is slot 1). A flat array dodges the
// struct's private `_pad` field so it const-initialises in .bss. The
// compile-time assert near the imports keeps the size in lock-step.
// M4a: the register-file buffer now spans the full extended R15 context —
// GuestRegisterFile (0x328) + sysreg array (0x328..0x528) + spill area
// (0x528..0x728) = 0x728 bytes = 229 u64 slots. Translated code addresses
// sysreg slots ([R15+0x328..]) and spill slots ([R15+0x528..]); a smaller
// buffer would let a spilled value or MSR write run off the end into adjacent
// BSS. The size is asserted against runtime::context::CTX_U64S below.
static mut M2_REGFILE: [u64; aether_translator::runtime::context::CTX_U64S] =
    [0u64; aether_translator::runtime::context::CTX_U64S];

/// M3 memory-store observation cell. A hypervisor static (low BSS, writable,
/// identity-mapped) whose host VA is seeded into guest X2; the translated
/// STR X0,[X2] writes 0x41 here, and LDR X1,[X2] reads it back.
static mut M3_OBS: u64 = 0;

/// M4b-2 synthetic-`__enable_mmu` page-table scratch: 5 contiguous, 4 KiB-aligned
/// pages of guest RAM (L0 / L1 / L2 / L3 / data) that the proof's translated block
/// turns into a live stage-1 mapping. The hypervisor pins the software-MMU window
/// to this static's address for the duration of the proof (then restores the
/// production handoff window before the dispatch loop). It is low-BSS, writable,
/// and identity-mapped, so the host-mode walker reads each table base as a raw
/// host pointer (the guest-PA == host-PA invariant the M2/M3/M4a proofs rely on).
/// Reuses the file's `Page4K` (`repr(C, align(4096))`) newtype so element 0 is
/// 4 KiB-aligned and the five pages are contiguous; every table/leaf base is a
/// valid 4 KiB-aligned guest PA. The proof only touches it through raw pointer
/// arithmetic off the base address, never field access.
static mut M4B2_PT_SCRATCH: [Page4K; 5] = [
    Page4K([0u8; 4096]),
    Page4K([0u8; 4096]),
    Page4K([0u8; 4096]),
    Page4K([0u8; 4096]),
    Page4K([0u8; 4096]),
];

/// Structural gate before CALLing a translated block: forms a byte slice from
/// the block's host VA and delegates to the translator's `block_bytes_are_safe`
/// (non-empty, ends in RET, no UD2). The `unsafe` slice formation lives here
/// because the translator crate is `#![deny(unsafe_code)]`; the policy itself
/// is the single shared, unit-tested checker. EVERY production path that
/// transfers control to JIT output (this M3/M4a loop and the svm.rs/vtx.rs NPF
/// resume sites) must pass through this before `enter_host_block`.
///
/// # Safety
/// `host_va` must point at `len` readable bytes of translator-produced code.
unsafe fn block_is_safe_to_enter(host_va: usize, len: usize) -> bool {
    if host_va == 0 || len == 0 {
        return false;
    }
    // SAFETY: caller guarantees `host_va`/`len` describe a readable code block.
    let code = unsafe { core::slice::from_raw_parts(host_va as *const u8, len) };
    block_bytes_are_safe(code)
}

/// Enter a translated, RET-terminated block in SVM host mode with R15 = `ctx`.
/// Preserves every Win64 nonvolatile GPR (RBX, RBP, RSI, RDI, R12–R15); the
/// block scratches allocatable GPRs and uses R15 as the register-file base.
/// `#[inline(never)]` so the CALL/RET pairing is never optimised away. This
/// mirrors the host-verified `tests/at_exec_proof.rs::enter_block` trampoline.
///
/// # Safety
/// `code` must point at a valid RET-terminated x86 block produced by the
/// translator; `ctx` must point at a buffer of at least 0x328 bytes the block
/// may read/write.
#[inline(never)]
unsafe fn enter_host_block(code: *const u8, ctx: *mut u64) {
    // SAFETY: caller's contract; we save/restore all Win64 nonvolatiles.
    unsafe {
        core::arch::asm!(
            "push rbx", "push rbp", "push rsi", "push rdi",
            "push r12", "push r13", "push r14", "push r15",
            "mov r15, {ctx}",
            "call {code}",
            "pop r15", "pop r14", "pop r13", "pop r12",
            "pop rdi", "pop rsi", "pop rbp", "pop rbx",
            ctx = in(reg) ctx,
            code = in(reg) code,
            // R15 is CONTEXT_REG and is written by `mov r15, {ctx}`; declare it
            // clobbered so the allocator never places {ctx}/{code} in R15 (which
            // would corrupt the input before `call {code}` -> blind triple-fault).
            lateout("r15") _,
            clobber_abi("C"),
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// M4b-2-bootwire: live-guest ARM64 register-file context + NPF block entry.
//
// The translator runs in host-mode: a translated block is a RET-terminated x86
// subroutine that reads/writes the ARM64 guest register file via [R15+disp].
// The live guest therefore needs ONE persistent context buffer (NPF_GUEST_CTX)
// that survives across blocks — unlike the per-proof M2_REGFILE which is reseeded
// for each isolated M-proof. svm::handle_vm_exit's NPF path calls
// enter_translated_block_from_npf() to run the block at the faulting PC and read
// back the next PC the block computed into its PC slot.
// ─────────────────────────────────────────────────────────────────────────────

/// Flat slot index of the guest PC inside the R15 context (byte 0x100 / 8).
const NPF_PC_SLOT: usize = 0x100 / 8;

/// Live guest ARM64 register file consulted by every block entered from the
/// NPF dispatch path. Layout-identical to the translator's extended R15 context
/// (GuestRegisterFile + sysreg array + spill area). Seeded once with the RO ID
/// sysregs on first NPF entry, then carried forward across blocks so guest
/// register state (and PC) persists across the translate/dispatch loop.
static mut NPF_GUEST_CTX: [u64; aether_translator::runtime::context::CTX_U64S] =
    [0u64; aether_translator::runtime::context::CTX_U64S];

/// True once `NPF_GUEST_CTX` has been seeded with `seed_sysregs`.
static mut NPF_CTX_SEEDED: bool = false;

/// Sysreg slot indices (relative to `SYSREG_SLOT0`) the fetch path consults.
/// Mirrors `aether_translator::runtime::mmu::{SLOT_SCTLR}`; SCTLR bit 0 is the
/// MMU-enable (`M`) bit.
const NPF_SLOT_SCTLR: usize = aether_translator::runtime::mmu::SLOT_SCTLR;
/// `SCTLR_EL1.M` — MMU enable bit.
const NPF_SCTLR_M: u64 = 1 << 0;

/// Ensure `NPF_GUEST_CTX` is seeded (idempotent) and return its base pointer.
///
/// The fetch path ([`npf_fetch_guest_pa`]) and the block-entry path
/// ([`enter_translated_block_from_npf`]) both need the live context: the former
/// to read SCTLR/TTBR/TCR for the walk, the latter as R15. Seeding the RO ID
/// sysregs once here keeps the two callers coherent.
///
/// # Safety
/// Single-core EL2 dispatch; no concurrent writer of `NPF_GUEST_CTX`.
unsafe fn npf_ctx_ptr() -> *mut u64 {
    // SAFETY: single-core EL2 dispatch.
    unsafe {
        if !*ptr::addr_of!(NPF_CTX_SEEDED) {
            let rf = &mut *ptr::addr_of_mut!(NPF_GUEST_CTX);
            aether_translator::runtime::context::seed_sysregs(rf);
            *ptr::addr_of_mut!(NPF_CTX_SEEDED) = true;
        }
        ptr::addr_of_mut!(NPF_GUEST_CTX) as *mut u64
    }
}

/// True iff the live guest has its MMU enabled (`SCTLR_EL1.M == 1`). When false
/// (early boot) instruction fetch is flat (PC == guest PA); when true the PC is
/// virtual and must be walked.
///
/// # Safety
/// Same single-core EL2 contract as [`npf_ctx_ptr`].
pub(crate) unsafe fn npf_mmu_enabled() -> bool {
    // SAFETY: single-core EL2 dispatch.
    unsafe {
        let ctx = npf_ctx_ptr();
        let sctlr = *ctx.add(
            aether_translator::runtime::context::SYSREG_SLOT0 + NPF_SLOT_SCTLR,
        );
        sctlr & NPF_SCTLR_M != 0
    }
}

/// M4b-2c: translate the ARM64 fetch `pc` (a VIRTUAL address once the guest
/// enables its MMU) to a guest PA from which the instruction BYTES are read.
///
/// * MMU off (`SCTLR.M == 0`): returns `Some(pc)` (flat — PC == guest PA), the
///   behaviour the live boot path had before the walker was wired in.
/// * MMU on, walk succeeds: returns `Some(guest_pa)` (== host PA in the handoff
///   identity window) — the dispatcher then reads instruction bytes from the
///   NPT window at that PA. The JIT BLOCK-CACHE KEY stays the VA `pc`; only the
///   byte source changes.
/// * MMU on, walk faults: returns `None` after the walker records a pending
///   INSTRUCTION Abort (`ESR_EL1.EC = 0x21`, FAR = `pc`) in `NPF_GUEST_CTX` for
///   the M4b-3 exception-injection path to consume.
///
/// # Safety
/// Must run in SVM host mode with the live guest page tables resident in the
/// (identity-mapped) guest window the walker is pinned to.
pub(crate) unsafe fn npf_fetch_guest_pa(pc: u64) -> Option<u64> {
    // SAFETY: single-core EL2 dispatch; ctx is the seeded NPF_GUEST_CTX base.
    unsafe {
        let ctx = npf_ctx_ptr();
        let pa = aether_translator::runtime::mmu::aether_mmu_fetch_pa(ctx, pc);
        if pa == aether_translator::runtime::mmu::XLATE_FAULT {
            // Distinguish a real fault from a (legitimate) flat translation to
            // guest PA 0: the walker only returns the fault sentinel when MMU is
            // ON (flat path returns the VA unchanged, and the guest window never
            // contains PA 0). So sentinel here == genuine fetch fault.
            return None;
        }
        Some(pa)
    }
}

/// Enter the translated block at ARM64 `pc` against the live guest context and
/// return the next guest PC the block left in its PC slot.
///
/// Preconditions (the caller — svm::handle_vm_exit — guarantees these):
///   * `aether_dbt_translate_block(pc, ..)` already returned `Ok` for this `pc`.
///   * `block_bytes_are_safe` (via `block_is_safe_to_enter`) passed.
///
/// Returns `Some(next_pc)` after running the block, or `None` if the block's
/// host VA could not be resolved or the safety gate failed (fail-loud: the
/// caller terminates rather than entering unvetted bytes).
///
/// # Safety
/// Must be called in SVM host mode with the JIT cache mapped executable in the
/// active NPT and the translator runtime initialised. The block at `pc` must be
/// translator-produced, RET-terminated x86.
/// Budget for on-screen exception/IRQ event logging from the dispatch loop, so a
/// future flood (e.g. live timer IRQs once the GIC + DAIF masking are fully
/// wired) cannot bury the framebuffer. Decremented per event line; once
/// exhausted the events STILL take effect — only their logging is suppressed.
static mut DBT_EVENT_LOG_BUDGET: u32 = 512;

/// Returns true (and consumes one unit) if an exc/IRQ event line may be printed.
#[inline]
unsafe fn dbt_event_log_ok() -> bool {
    unsafe {
        let p = ptr::addr_of_mut!(DBT_EVENT_LOG_BUDGET);
        if *p == 0 {
            return false;
        }
        *p -= 1;
        if *p == 0 {
            dual_puts(b"[dbt] (event-log budget exhausted -- further exc/irq lines suppressed)\n");
        }
        true
    }
}

pub(crate) unsafe fn enter_translated_block_from_npf(pc: u64) -> Option<u64> {
    // SAFETY: single-core EL2 dispatch; no concurrent writer of NPF_GUEST_CTX.
    unsafe {
        // Shared seeding with the fetch path: npf_ctx_ptr() ensures the same
        // live context the fetch walked is the one the block runs against.
        use aether_translator::runtime::context::SYSREG_SLOT0;
        use aether_translator::runtime::{exceptions, gic, psci, sysreg_rt};
        let ctx = npf_ctx_ptr();
        // M4b-4/M4b-5: advance the virtual count from the host TSC, SCALED to
        // the guest's 24 MHz CNTFRQ_EL0, so CNTVCT_EL0 (and the guest's delay
        // loops / scheduler tick) track roughly-real wall-clock time instead of
        // running ~125× fast off the raw ~3 GHz RDTSC.
        sysreg_rt::aether_timer_set_now(host_virtual_count());

        // Point the block at the faulting PC. A correctly-lifted block reads its
        // own constant PC at terminators, but seeding it keeps the context's PC
        // slot coherent for any block that consults PC mid-stream.
        (*ptr::addr_of_mut!(NPF_GUEST_CTX))[NPF_PC_SLOT] = pc;

        let (host_va, len) = aether_dbt_block_host_va(pc)?;
        if !block_is_safe_to_enter(host_va, len) {
            return None;
        }
        enter_host_block(host_va as *const u8, ctx);
        let ctx_slice = core::slice::from_raw_parts_mut(
            ctx,
            aether_translator::runtime::context::CTX_U64S,
        );

        // M4b-3 SYNCHRONOUS abort: if a load/store in the block faulted
        // (early-RET with a pending Data Abort recorded by the walker), inject
        // the EL1 exception now — the PC slot is left at `VBAR_EL1 + 0x200`
        // (the handler), ELR_EL1 at the block's resume PC. (ELR is block-granular
        // for a mid-block data abort — the documented approximation until
        // per-instruction PC stamping lands; bring-up faults are
        // first-instruction.)
        // Capture the walker-recorded pending FAR/ESR (sub-slots 57/58) BEFORE
        // take_pending_abort consumes them, so the log shows the real fault.
        let pend_far = ctx_slice[SYSREG_SLOT0 + 57];
        let pend_esr = ctx_slice[SYSREG_SLOT0 + 58];

        // (Phase-D linear-map fault handling has moved into the walker's
        // kernel-image fallback path — see aether_mmu_set_kimg_fallback.)

        if exceptions::take_pending_abort(ctx_slice) {
            if dbt_event_log_ok() {
                dual_puts(b"[exc] DATA ABORT -> EL1 vector=");
                dual_puthex64(ctx_slice[NPF_PC_SLOT]);
                dual_puts(b" far=");
                dual_puthex64(pend_far);
                dual_puts(b" esr=");
                dual_puthex64(pend_esr);
                dual_puts(b"\n");
            }
            return Some(ctx_slice[NPF_PC_SLOT]);
        }

        // M4b-4 PSCI side effect: an HVC SYSTEM_OFF / SYSTEM_RESET / CPU_OFF in
        // the block requested a platform action — stop the dispatch loop (a
        // clean halt stands in for power-off / reset until warm-reset is wired).
        match psci::aether_hvc_take_action() {
            psci::HvcPlatformAction::None => {}
            other => {
                dual_puts(b"[psci] platform action -> halt: 0x");
                dual_puthex64(other as u64);
                dual_puts(b"\n");
                return None;
            }
        }

        // M4b-4 ASYNCHRONOUS IRQ: deliver a pending, unmasked interrupt at this
        // instruction boundary. Dormant until the guest enables a source through
        // the GICD/GICR MMIO config (the documented integration boundary) — until
        // then `aether_pending_irq` is spurious and this is a no-op.
        let pending_irq = sysreg_rt::aether_pending_irq();
        if exceptions::irqs_unmasked(ctx_slice) && pending_irq != gic::SPURIOUS_INTID {
            exceptions::inject_irq(ctx_slice);
            if dbt_event_log_ok() {
                dual_puts(b"[irq] INJECT intid=");
                dual_puthex64(pending_irq as u64);
                dual_puts(b" -> EL1 vector=");
                dual_puthex64(ctx_slice[NPF_PC_SLOT]);
                dual_puts(b"\n");
            }
            return Some(ctx_slice[NPF_PC_SLOT]);
        }

        Some((*ptr::addr_of!(NPF_GUEST_CTX))[NPF_PC_SLOT])
    }
}

/// Host time-stamp counter (RDTSC), the raw monotonic source.
#[inline]
fn host_tsc() -> u64 {
    // SAFETY: RDTSC is unconditionally available on x86_64.
    unsafe { core::arch::x86_64::_rdtsc() }
}

// ── M4b-5: TSC → CNTFRQ scaling ──────────────────────────────────────────────
// The guest reads CNTFRQ_EL0 as 24 MHz (the translator's DEFAULT_CNTFRQ) and
// derives every delay loop and scheduler tick from CNTVCT_EL0. Feeding raw
// RDTSC (~3 GHz) into that 24 MHz counter runs the guest's clock ~125× fast:
// udelay() returns instantly, the tick storms, time is meaningless. We scale
// RDTSC down to a 24 MHz virtual ARM generic-counter tick, anchored at the
// first sample so the counter starts near 0 and the u128 product never
// overflows in practice.
const GUEST_CNTFRQ_HZ: u64 = aether_translator::runtime::sysreg_rt::DEFAULT_CNTFRQ;
static mut TSC_BASE: u64 = 0;
static mut TSC_HZ: u64 = 0;

#[inline]
fn cpuid(leaf: u32, sub: u32) -> core::arch::x86_64::CpuidResult {
    // __cpuid_count is a safe intrinsic on x86_64 (CPUID is always available).
    core::arch::x86_64::__cpuid_count(leaf, sub)
}

/// Best-effort host TSC frequency in Hz. Prefers CPUID.15H (crystal × ratio),
/// then CPUID.16H (base MHz), then a 3 GHz fallback. Exact accuracy is not
/// required for bring-up — the goal is a roughly-right rate, not wall-clock.
fn detect_tsc_hz() -> u64 {
    let max_leaf = cpuid(0, 0).eax;
    if max_leaf >= 0x15 {
        let r = cpuid(0x15, 0);
        // EAX = ratio denominator, EBX = numerator, ECX = nominal crystal Hz.
        if r.eax != 0 && r.ebx != 0 && r.ecx != 0 {
            return (r.ecx as u64) * (r.ebx as u64) / (r.eax as u64);
        }
    }
    if max_leaf >= 0x16 {
        let r = cpuid(0x16, 0);
        // EAX = processor base frequency in MHz.
        if r.eax != 0 {
            return (r.eax as u64) * 1_000_000;
        }
    }
    3_000_000_000
}

/// The guest's virtual ARM generic counter (`CNTVCT_EL0`): RDTSC scaled to
/// `GUEST_CNTFRQ_HZ`, anchored at the first call. Monotonic and roughly
/// wall-clock-correct so the kernel's timekeeping behaves.
fn host_virtual_count() -> u64 {
    let now = host_tsc();
    // SAFETY: single-core EL2 dispatch; one-time lazy init of the anchor + rate.
    unsafe {
        if *ptr::addr_of!(TSC_HZ) == 0 {
            *ptr::addr_of_mut!(TSC_HZ) = detect_tsc_hz();
            *ptr::addr_of_mut!(TSC_BASE) = now;
        }
        let base = *ptr::addr_of!(TSC_BASE);
        let hz = *ptr::addr_of!(TSC_HZ);
        let delta = now.wrapping_sub(base) as u128;
        ((delta * GUEST_CNTFRQ_HZ as u128) / hz as u128) as u64
    }
}

/// 4 KiB page mask for the guest instruction-window read.
const GUEST_PAGE_BYTES: u64 = 0x1000;

/// Walk the host CR3 page tables and OR-in PTE.W on every leaf covering
/// the staged handoff RAM range, so lifted ARM64 stores (which translate
/// to host writes via aether_mmu_store) don't trip a host #PF on pages
/// OVMF marked W=0. Safer than clearing CR0.WP. Idempotent.
///
/// PML4[i] -> PDPT -> PD -> PT, 4 KiB granularity. Large pages (PS=1 at
/// PDPT/PD) are NOT split; instead we OR-in W on the large-page entry
/// itself, which makes the whole 1 GiB / 2 MiB region writable. Since the
/// handoff region is contiguous and OVMF's identity-map is well-formed,
/// this fully covers our needs.
///
/// # Safety
/// Single-core EL2/VMX-root context; runs post-ExitBootServices when we
/// own CR3 fully. Modifies present PTEs only — never adds new mappings.
unsafe fn host_pt_make_handoff_rw() {
    unsafe {
        // Bootstrap: the host PT pages themselves may be mapped W=0 by OVMF
        // (to prevent the kernel from modifying its own page tables). To
        // OR-in W on PT entries, we must transiently allow writes to W=0
        // pages — clear CR0.WP for the duration of the walk, then restore
        // the original CR0 (with WP intact).
        let saved_cr0: u64;
        core::arch::asm!("mov {}, cr0", out(reg) saved_cr0, options(nomem, nostack));
        core::arch::asm!("mov cr0, {}", in(reg) saved_cr0 & !(1u64 << 16),
                         options(nomem, nostack));
        let cr3: u64;
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack));
        let pml4 = (cr3 & 0x0000_FFFF_FFFF_F000) as *mut u64;
        // The dispatch window may not be pinned yet at EBS time (it's set
        // post-handoff). Use a fixed-wide sweep covering ALL of low RAM
        // (0..4 GiB) — the entire conventional-RAM range the guest could
        // touch via lifted stores. UEFI identity-maps low 4 GiB so PML4[0]
        // walking from VA==PA gives us every host-backed page.
        let win_base: u64 = 0;
        let win_size: u64 = 4 * 1024 * 1024 * 1024;
        let win_end = win_base.saturating_add(win_size);
        // Cover the entire window in 4 KiB-granularity, but stop early when a
        // PDPT/PD entry has PS=1 (large page) — we OR-in W on the large entry.
        let mut va = win_base & !0xFFFu64;
        while va < win_end {
            let pml4_idx = ((va >> 39) & 0x1FF) as isize;
            let pml4e = core::ptr::read_volatile(pml4.offset(pml4_idx));
            if pml4e & 1 == 0 { va = (va + (1u64 << 39)) & !((1u64 << 39) - 1); continue; }
            core::ptr::write_volatile(pml4.offset(pml4_idx), pml4e | 2);
            let pdpt = (pml4e & 0x0000_FFFF_FFFF_F000) as *mut u64;
            let pdpt_idx = ((va >> 30) & 0x1FF) as isize;
            let pdpte = core::ptr::read_volatile(pdpt.offset(pdpt_idx));
            if pdpte & 1 == 0 { va = (va + (1u64 << 30)) & !((1u64 << 30) - 1); continue; }
            core::ptr::write_volatile(pdpt.offset(pdpt_idx), pdpte | 2);
            if pdpte & (1 << 7) != 0 {
                // 1 GiB large page — OR W is enough; advance by 1 GiB.
                va = (va + (1u64 << 30)) & !((1u64 << 30) - 1);
                continue;
            }
            let pd = (pdpte & 0x0000_FFFF_FFFF_F000) as *mut u64;
            let pd_idx = ((va >> 21) & 0x1FF) as isize;
            let pde = core::ptr::read_volatile(pd.offset(pd_idx));
            if pde & 1 == 0 { va = (va + (1u64 << 21)) & !((1u64 << 21) - 1); continue; }
            core::ptr::write_volatile(pd.offset(pd_idx), pde | 2);
            if pde & (1 << 7) != 0 {
                // 2 MiB large page — OR W on this PDE; advance 2 MiB.
                va = (va + (1u64 << 21)) & !((1u64 << 21) - 1);
                continue;
            }
            let pt = (pde & 0x0000_FFFF_FFFF_F000) as *mut u64;
            let pt_idx = ((va >> 12) & 0x1FF) as isize;
            let pte = core::ptr::read_volatile(pt.offset(pt_idx));
            if pte & 1 != 0 {
                core::ptr::write_volatile(pt.offset(pt_idx), pte | 2);
            }
            va = va + 0x1000;
        }
        // Flush global TLB so the new W bits take effect.
        let cr3_v: u64;
        core::arch::asm!("mov {}, cr3", out(reg) cr3_v, options(nomem, nostack));
        core::arch::asm!("mov cr3, {}", in(reg) cr3_v, options(nomem, nostack));
        // Restore CR0.WP. Now WP=1 protects hypervisor .text from buggy
        // lifted stores while the OR-W we just applied keeps the handoff
        // RAM pages writable via PTE.W=1.
        core::arch::asm!("mov cr0, {}", in(reg) saved_cr0, options(nomem, nostack));
        dual_puts(b"[x86] host PT: handoff window forced RW\n");
    }
}

/// Return a host pointer + length for reading the guest instruction stream at
/// guest PA `guest_pa`, clamped to the pinned handoff window AND a single 4 KiB
/// page (a translated block never spans a page — the walker is page-granular and
/// `translate_block` caps at the page boundary). In the handoff window
/// guest PA == host PA (UEFI identity-maps the low 4 GiB), so the bytes are read
/// directly; `None` if `guest_pa` is outside the window.
///
/// # Safety
/// The returned pointer is only valid for `len` bytes within one identity-mapped
/// guest page; the caller must not read past it.
/// Resolve the live guest-RAM window (base, size). Returns the runtime-pinned
/// span set from the prepared handoff (`DISPATCH_WINDOW_*`); falls back to the
/// legacy `STAGED_BOOT_IMG_PA`/`HANDOFF_REGION_SIZE` constants only when unset
/// (0 = no real handoff armed, e.g. synthetic/pre-staged setups). The walker
/// window pin, `read_guest_window_identity`, and the EPT/NPT mapped range MUST
/// all derive from this so the kernel's runtime PA is never rejected.
fn dispatch_window() -> (u64, u64) {
    // SAFETY: single-core EL2 dispatch; these are set once before the loop.
    unsafe {
        let base = *ptr::addr_of!(DISPATCH_WINDOW_BASE);
        let size = *ptr::addr_of!(DISPATCH_WINDOW_SIZE);
        if base != 0 && size != 0 {
            (base, size)
        } else {
            (crate::android_handoff::STAGED_BOOT_IMG_PA,
             crate::android_handoff::HANDOFF_REGION_SIZE)
        }
    }
}

unsafe fn read_guest_window_identity(guest_pa: u64, max_len: usize) -> Option<(*const u8, usize)> {
    let (base, size) = dispatch_window();
    if guest_pa < base || guest_pa.wrapping_sub(base) >= size {
        return None;
    }
    let page_off = (guest_pa & (GUEST_PAGE_BYTES - 1)) as usize;
    let page_left = (GUEST_PAGE_BYTES as usize) - page_off;
    let window_left = (size - (guest_pa - base)) as usize;
    let len = max_len.min(page_left).min(window_left);
    if len == 0 {
        return None;
    }
    Some((guest_pa as *const u8, len))
}

/// M4b-5: the vendor-neutral HOST-MODE dispatch loop — the live path that grinds
/// a real ARM64 GKI kernel toward `init` on both AMD and Intel silicon.
///
/// This is the SAME mechanism the M2/M3/M4a/M4b on-silicon proofs used (host-mode
/// `CALL` into translator-produced RET-terminated x86 with R15 = the live guest
/// context), now fed the real kernel instead of a synthetic program. It replaces
/// the VMRUN-into-guest model on the live path: an x86 core cannot execute ARM64
/// bytes, so VMRUN'ing into `kernel_entry_pa` (ARM64 GKI) decodes them as x86,
/// faults with no guest IDT, and triple-faults (SVM SHUTDOWN 0x7F). Instead
/// AETHER translates each block and runs it ITSELF, reading/writing guest memory
/// through the software MMU walker + the MMIO emulator. No per-block VMEXIT, no
/// NX/NPF dependency, and Intel/AMD share one loop.
///
/// Seeds the guest context from the handoff's initial registers (x0 = DTB PA,
/// x1..x3 = 0, SP, pc = kernel entry — the ARM64 Linux boot protocol) and loops:
/// fetch (software MMU walk / flat) → read the guest instruction window →
/// cold-translate the block → safety-gate → host-mode enter → advance PC (and
/// deliver any pending data abort / IRQ / PSCI side effect, handled inside
/// [`enter_translated_block_from_npf`]).
///
/// # Safety
/// Must run after the translator runtime is initialised, in the single-core EL2
/// dispatch context. Diverges (halts) on translate failure, an unsupported
/// (UD2) block, a fetch fault with no handler, a PSCI power-off/reset, or the
/// iteration cap.
unsafe fn run_android_dispatch_loop(regs: crate::android_handoff::DbtInitialRegs) -> ! {
    unsafe {
        // aether_dbt_{translate_block,block_host_va,last_failure} + AetherDbtResult
        // are already imported at module scope; only MAX_INSNS_PER_BLOCK is new.
        use aether_translator::dbt::MAX_INSNS_PER_BLOCK;
        const WINDOW_BYTES: usize = MAX_INSNS_PER_BLOCK * 4;

        // Pin the software-MMU guest-PA window to the exact handoff span (the
        // walker confines every table base + leaf output here — No-Boundary).
        // dispatch_window() returns the REAL runtime span (h.region_pa/size),
        // not the STAGED_BOOT_IMG_PA constant, so the kernel's actual PA (near
        // 4 GiB on the UEFI-alloc path) is in-window and the first fetch lands.
        let (win_base, win_size) = dispatch_window();
        aether_translator::runtime::mmu::aether_mmu_set_window(win_base, win_size);
        // Register the MMIO emulator so guest UART / GIC / virtio accesses route
        // to mmio_emu instead of faulting (they fall outside the RAM window).
        aether_translator::runtime::mmu::aether_set_mmio_handler(
            crate::mmio_emu::aether_mmio_bridge,
        );
        // Clear any software-TLB residue left by the boot proof programs.
        aether_translator::runtime::mmu::aether_mmu_flush_all();

        // Phase-D kernel-image VA->PA fallback. Linux's __create_page_tables in
        // head.S maps `[_text, ALIGN(_end, 2 MiB))`, but the kernel later
        // accesses some VAs just past that (e.g. memblock initdata arrays).
        // It hits a translation fault, calls is_spurious_el1_translation_fault
        // which does `AT S1E1R + read PAR_EL1`; our software MMU doesn't model
        // AT, PAR stays 0, kernel decides "spurious" and ERETs back. Walker
        // refaults forever.
        // Register a fallback that resolves kernel-image VAs (the full kimg
        // VA region in 0xFFFFFFC0_xxxxxxxx) by VA-offset translation to the
        // matching PA in the handoff window. The walker only consults this
        // when the regular TTBR1 walk fails; if both fail, the abort is
        // injected normally.
        //
        // Kernel image VA base for VA_BITS=39 GKI is 0xFFFFFFC0_08000000 (the
        // kernel's _text). The PA base is `regs.pc` — the seeded kernel entry
        // PC, which IS the kernel image's _text PA.
        let kimg_va_base: u64 = 0xFFFF_FFC0_0800_0000;
        let kimg_pa_base: u64 = regs.pc;
        // Cover the entire 1 GiB region of L1[256] in TTBR1 (the kernel-image
        // area). Initial Linux mapping only covers _text..ALIGN(_end,2MiB);
        // anything past that hits this fallback.
        let kimg_span: u64 = 1024 * 1024 * 1024;
        aether_translator::runtime::mmu::aether_mmu_set_kimg_fallback(
            kimg_va_base, kimg_pa_base, kimg_span,
        );

        // ── M4b-6 fixmap probe ──────────────────────────────────────────────
        // Arm the walk tracer over the top 256 MiB of the TTBR1 kernel-VA
        // space. For CONFIG_ARM64_VA_BITS_39 (the GKI default) FIXADDR_TOP and
        // the FIX_FDT slot sit near the very top of kernel VA, so any walk
        // here is overwhelmingly likely to be the kernel's fdt fixmap install
        // / fdt header read. Captures up to MMU_TRACE_MAX walks: per-level
        // descriptors + final PA, surfaced below in the dbt heartbeat. If the
        // walker rejects or returns the wrong PA, the trace prints the exact
        // descriptor chain so we can compare against the expected mapping
        // (dt_virt -> 0x7be00000 + page-offset).
        // Widen to the WHOLE TTBR1 kernel-VA half (bit-55 set region) so we
        // catch the first high-VA walks the kernel does — fixmap might be at
        // any offset, and the previous narrow top-256-MiB window caught zero.
        // Phase B step 2/3: narrow trace to the FIXMAP VA region (top of
        // TTBR1 — for VA_BITS=39, FIXADDR_TOP is near 0xffff_fffe_ff800000).
        // Capture only walks targeting that area so the ring shows exactly
        // what the kernel sees when fixmap_remap_fdt reads dt_virt. A PASS
        // walk with PA in [0x7be00000, 0x7c000000) means fixmap is wired
        // correctly and the bug is elsewhere; a FAULT (st with high bit set)
        // means the kernel's create_mapping_noalloc didn't install the PTE
        // our walker expects.
        // Phase B step 3 (refined): the actual FIX_FDT slot lives at
        // dt_virt = 0xFFFF_FFFD_FDC0_0000 (proven by disasm of
        // fixmap_remap_fdt at image+0x19ebbc4: mov x19,#0xfdc00000 +
        // movk #0xfffd,lsl 32 + movk #0xffff,lsl 48). Cover a comfortable
        // slab around it to also catch surrounding fixmap pages.
        aether_translator::runtime::mmu::aether_mmu_trace_range(
            0xFFFF_FFFD_F000_0000,
            0xFFFF_FFFE_0000_0000,
        );
        // Ring-buffer mode: kernel reaches its DTB fixmap read LATE; one-shot
        // capacity-16 trace fills up with early kernel-text walks long before
        // the interesting fixmap walk. Ring keeps the LAST 16 high-VA walks
        // so the dump at exit contains the freshest traffic, which should
        // include the DTB read (fdt_check_header) that triggers the panic.
        aether_translator::runtime::mmu::aether_mmu_trace_set_ring(true);
        // Also probe the DTB PA region directly — any walk whose final PA
        // lands here is the kernel reading the device tree.
        aether_translator::runtime::mmu::aether_mmu_trace_pa_range(
            0x7BE0_0000, 0x7C00_0000,
        );

        // Seed the live guest register file: x0..x30 (slots 0..30), SP (slot
        // 0xF8/8 = 31), PC (slot 0x100/8 = 32). npf_ctx_ptr() seeds the RO ID
        // sysregs on first touch.
        let ctx = npf_ctx_ptr();
        for i in 0..31usize {
            *ctx.add(i) = regs.x[i];
        }
        *ctx.add(0xF8 / 8) = regs.sp;
        *ctx.add(NPF_PC_SLOT) = regs.pc;

        dual_puts(b"[x86] host-mode dispatch loop: entry pc=");
        dual_puthex64(regs.pc);
        dual_puts(b" x0(dtb)=");
        dual_puthex64(regs.x[0]);
        dual_puts(b" sp=");
        dual_puthex64(regs.sp);
        dual_puts(b"\n");

        // ── On-screen observability for the live kernel grind ────────────────
        // DBT_TRACE_FIRST  — trace EVERY one of the first N blocks (iter, pc, raw
        //   ARM64 insn) so the opening trajectory is visible, then one line per
        //   TRACE_PERIOD blocks (a heartbeat that also names the live pc/insn).
        // NO_PROGRESS_LIMIT — a block whose next-PC equals the PC just run,
        //   repeated this many times with no abort/IRQ/PSCI side effect, is a
        //   stuck self-loop (cpu_park / panic `b .` / poll on state this single-
        //   stepped model never changes) → report pc+insn and halt instead of
        //   spinning silently to MAX_ITERS.
        // FETCH_ABORT_STREAK_MAX — an instruction abort whose handler vector is
        //   itself unfetchable re-faults forever → break after this many in a row.
        const DBT_TRACE_FIRST: u64 = 400; // first N *distinct* blocks (loops collapsed)
        const TRACE_PERIOD: u64 = 0x1_0000; // heartbeat every 65536 blocks
        // Phase-E: raised from 5M to 100M. The original 5M cap was hitting
        // legitimate long bounded loops in early boot (e.g. clear_resource_busy
        // iterating thousands of memblock entries — a `subs x8,x8,#1; b.ne`
        // that just takes a while). 100M still catches a true cpu_park /
        // panic-spin in a few seconds of wall-clock.
        const NO_PROGRESS_LIMIT: u64 = 100_000_000;
        const FETCH_ABORT_STREAK_MAX: u32 = 16;
        let mut same_pc: u64 = 0;
        let mut fetch_abort_streak: u32 = 0;
        // Distinct-PC trace state: a translated self-loop (e.g. the
        // __create_page_tables PTE-fill `B.LS .-N`) re-enters the dispatcher at
        // the SAME pc every iteration. Collapse those into one line + a repeat
        // count so the trajectory stays readable and the live trace keeps
        // flowing while a bounded loop grinds (instead of going silent).
        let mut prev_traced_pc: u64 = u64::MAX;
        let mut loop_reps: u64 = 0;
        let mut distinct_blocks: u64 = 0;
        // Per-heartbeat delta trackers — answers "is the kernel still printing?"
        // and "is it visiting new code or oscillating?" without needing a long
        // post-run grep. Reset every TRACE_PERIOD when the heartbeat fires.
        let mut hb_prev_pl011_w: u32 = 0;
        let mut hb_prev_distinct: u64 = 0;
        let mut hb_pc_min: u64 = u64::MAX;
        let mut hb_pc_max: u64 = 0;
        // Baseline fault count BEFORE the live dispatch starts (the M3/M4b-2
        // proofs intentionally trigger walker faults — those don't count).
        let live_flt_baseline: u32 =
            *ptr::addr_of!(aether_translator::runtime::mmu::MMU_FAULT_COUNT);
        let mut first_live_flt_logged = false;
        // One-shot trace-dump latch: emit the captured fixmap-probe walks the
        // first heartbeat after at least one walk is captured.
        let mut fixmap_trace_dumped = false;

        // ── Final-summary capture ────────────────────────────────────────────
        // The inline [dbt]/[exc] trace above streams to BOTH the framebuffer and
        // COM1 as the kernel runs, so on a heavy boot it scrolls the decisive
        // halt line off the top of the screen. To guarantee the post-mortem photo
        // is always readable, every break path records WHY into these locals; the
        // block after the loop clears the framebuffer and paints one concise box.
        // exit_code: 0=iter-cap 1=TranslateFail 2=block-UNSAFE 3=fetch-abort-storm
        //   4=NO-PROGRESS 5=PSCI/safety halt 6=fetch-window-OOR 7=fetch-no-handler
        //   8=host_va-miss-BUG.
        let mut exit_code: u32 = 0;
        let mut sum_pc:    u64 = 0; // faulting / last pc
        let mut sum_a:     u64 = 0; // word | vector | fetch_pa | next-pc context
        let mut sum_b:     u64 = 0; // kind | streak | repeats
        let mut sum_iter:  u64 = 0;
        let mut last_pc:   u64 = regs.pc;
        let mut last_insn: u32 = 0;

        const MAX_ITERS: u64 = 200_000_000;
        let mut iter: u64 = 0;
        loop {
            iter += 1;
            if iter > MAX_ITERS {
                dual_puts(b"[x86] dispatch iteration cap reached -- halting\n");
                exit_code = 0;
                sum_iter = iter;
                break;
            }
            let pc = (*ptr::addr_of!(NPF_GUEST_CTX))[NPF_PC_SLOT];
            last_pc = pc;

            // Phase B step 1: panic-site PC hook. When the block PC reaches
            // setup_machine_fdt's panic call (image+0x19e5824 ==
            // 0xffffffc0099e5824), inspect x20 to tell which arm of the
            // `if (!dt_virt || !early_init_dt_scan(dt_virt))` failed.
            //   x20 holds dt_virt (set at image+0x19e57ac after fixmap_remap_fdt
            //   returned, before either of the two panic branches).
            //   x20 == 0  => PATH A: fixmap_remap_fdt returned NULL.
            //   x20 != 0  => PATH B: early_init_dt_scan returned false.
            // Latches once so the dispatcher's stuck-in-park loop doesn't
            // spam the log.
            {
                static mut PHASE_B_HOOK_FIRED: bool = false;
                let fired = *ptr::addr_of!(PHASE_B_HOOK_FIRED);
                // Phase B step 3b: magic-check hook. Right after the
                // `cmp w8, w9` inside fixmap_remap_fdt (image+0x19ebbf4):
                //   x8 should hold rev(ldr w8, [x19]) — the byte-reversed
                //   first 4 bytes of the DTB at PA 0x7be00000 = 0xd00dfeed.
                //   x9 should hold MOVZ #0xfeed + MOVK #0xd00d lsl 16 =
                //   0xd00dfeed.
                // If x8 == 0xd00dfeed and the kernel still takes b.ne, then
                // CMP/NZCV is broken in our lifter. If x8 != 0xd00dfeed, then
                // LDR/REV is wrong (or the walker handed back wrong PA).
                // Hook at fixmap_remap_fdt entry to confirm it's reached.
                {
                    static mut ENTRY_HOOK_FIRED: bool = false;
                    if !*ptr::addr_of!(ENTRY_HOOK_FIRED) && pc == 0xFFFF_FFC0_099E_BB74 {
                        *ptr::addr_of_mut!(ENTRY_HOOK_FIRED) = true;
                        let g = &*ptr::addr_of!(NPF_GUEST_CTX);
                        dual_puts(b"[dbg] fixmap_remap_fdt ENTERED x0(dt_phys)=");
                        dual_puthex64(g[0]);
                        dual_puts(b" iter=");
                        dual_puthex64(iter);
                        dual_puts(b"\n");
                    }
                }
                // Hook right after the `bl __create_pgd_mapping` returns
                // (image+0x19ebbe4 = the LDR). If this fires, the mapping
                // call returned and we're about to read the magic.
                {
                    static mut LDR_HOOK_FIRED: bool = false;
                    if !*ptr::addr_of!(LDR_HOOK_FIRED) && pc == 0xFFFF_FFC0_099E_BBE4 {
                        *ptr::addr_of_mut!(LDR_HOOK_FIRED) = true;
                        let g = &*ptr::addr_of!(NPF_GUEST_CTX);
                        dual_puts(b"[dbg] LDR-MAGIC about to fire, x19(dt_virt)=");
                        dual_puthex64(g[19]);
                        dual_puts(b" iter=");
                        dual_puthex64(iter);
                        dual_puts(b"\n");
                        // Direct host read of the 16 bytes at the DTB PA the
                        // walker resolves to. If these are 0xd00dfeed etc.,
                        // the LDR/walker is the bug. If zero, something
                        // overwrote our DTB.
                        let dtb_pa = 0x7be0_0000u64 as *const u8;
                        dual_puts(b"[dbg]   host-direct read PA 0x7be00000 first16:");
                        let mut i = 0usize;
                        while i < 16 {
                            let b = *dtb_pa.add(i);
                            dual_puts(b" ");
                            let hi = (b >> 4) & 0xF;
                            let lo = b & 0xF;
                            let h_ch = if hi < 10 { b'0' + hi } else { b'a' + hi - 10 };
                            let l_ch = if lo < 10 { b'0' + lo } else { b'a' + lo - 10 };
                            dual_puts(&[h_ch, l_ch]);
                            i += 1;
                        }
                        dual_puts(b"\n");
                    }
                }
                // Post-cmp outcome hooks (block starts). Magic check has just
                // resolved — these tell us which branch was taken and what x8
                // ended up as.
                {
                    static mut MATCH_HOOK_FIRED: bool = false;
                    static mut FAIL_HOOK_FIRED:  bool = false;
                    let g = &*ptr::addr_of!(NPF_GUEST_CTX);
                    if !*ptr::addr_of!(MATCH_HOOK_FIRED) && pc == 0xFFFF_FFC0_099E_BBFC {
                        *ptr::addr_of_mut!(MATCH_HOOK_FIRED) = true;
                        dual_puts(b"[dbg] MAGIC OK -> totalsize load. x8=");
                        dual_puthex64(g[8] & 0xFFFF_FFFF);
                        dual_puts(b"\n");
                    }
                    if !*ptr::addr_of!(FAIL_HOOK_FIRED) && pc == 0xFFFF_FFC0_099E_BC10 {
                        *ptr::addr_of_mut!(FAIL_HOOK_FIRED) = true;
                        dual_puts(b"[dbg] MAGIC FAIL -> NULL path. x8(rev)=");
                        dual_puthex64(g[8] & 0xFFFF_FFFF);
                        dual_puts(b" x9(expected)=");
                        dual_puthex64(g[9] & 0xFFFF_FFFF);
                        dual_puts(b" x19(dt_virt)=");
                        dual_puthex64(g[19]);
                        dual_puts(b"\n");
                    }
                }
                // Phase C Bug C: SCTLR.M transition detector and high-VA
                // jump (br x8) reach detector.
                {
                    static mut MMU_ON_LOGGED: bool = false;
                    static mut BR_X8_LOGGED: bool = false;
                    const SR0: usize =
                        aether_translator::runtime::context::SYSREG_SLOT0;
                    let g = &*ptr::addr_of!(NPF_GUEST_CTX);
                    let sctlr_m_now = g[SR0 + 0] & 1;
                    if !*ptr::addr_of!(MMU_ON_LOGGED) && sctlr_m_now == 1 {
                        *ptr::addr_of_mut!(MMU_ON_LOGGED) = true;
                        dual_puts(b"[dbg] MMU ENABLED first observed at block_pc=");
                        dual_puthex64(pc);
                        dual_puts(b" sctlr=");
                        dual_puthex64(g[SR0 + 0]);
                        dual_puts(b" iter=");
                        dual_puthex64(iter);
                        dual_puts(b"\n");
                    }
                    // The high-VA relocation jump in __primary_switch
                    // (image+0xf76510 = PA 0x7cf76510). If this block ever
                    // runs, the kernel reached the post-MMU-enable BR x8;
                    // we can then check x8 to see the target VA.
                    if !*ptr::addr_of!(BR_X8_LOGGED) && pc == 0x7CF7_6510 {
                        *ptr::addr_of_mut!(BR_X8_LOGGED) = true;
                        dual_puts(b"[dbg] HIGH-VA JUMP reached: br x8 at 0x7cf76510 x8=");
                        dual_puthex64(g[8]);
                        dual_puts(b" iter=");
                        dual_puthex64(iter);
                        dual_puts(b"\n");
                    }
                }
                // C.1: GPR dump at the fault-entry block PC. The kernel
                // loaded x0=9 here and the LDRB triggers the spurious abort.
                // Dump x0..x30 + sp + sysreg snapshot so the upstream block
                // that wrote x0 wrong becomes traceable.
                {
                    static mut FAULT_GPR_FIRED: bool = false;
                    // Match BOTH the PA (kernel pre-MMU, what the heartbeat
                    // showed) AND the VA (post-MMU mapped through TTBR1).
                    if !*ptr::addr_of!(FAULT_GPR_FIRED)
                        && (pc == 0x7D9E_88BC || pc == 0xFFFF_FFC0_099E_88BC) {
                        *ptr::addr_of_mut!(FAULT_GPR_FIRED) = true;
                        let g = &*ptr::addr_of!(NPF_GUEST_CTX);
                        const SR0: usize =
                            aether_translator::runtime::context::SYSREG_SLOT0;
                        dual_puts(b"[dbg] FAULT BLOCK ENTRY pc=0xffffffc0099e88bc iter=");
                        dual_puthex64(iter);
                        dual_puts(b"\n");
                        let mut r = 0usize;
                        while r < 31 {
                            dual_puts(b"[dbg]   x");
                            dual_puthex64(r as u64);
                            dual_puts(b"=");
                            dual_puthex64(g[r]);
                            dual_puts(b"\n");
                            r += 1;
                        }
                        dual_puts(b"[dbg]   sp=");
                        dual_puthex64(g[0xF8 / 8]);
                        dual_puts(b" sctlr=");
                        dual_puthex64(g[SR0 + 0]);
                        dual_puts(b" vbar=");
                        dual_puthex64(g[SR0 + 6]);
                        dual_puts(b" ttbr0=");
                        dual_puthex64(g[SR0 + 1]);
                        dual_puts(b" ttbr1=");
                        dual_puthex64(g[SR0 + 2]);
                        dual_puts(b"\n");
                    }
                }
                // Phase-D CRC32 fault diagnostics. The kernel hits a translation
                // fault on a CRC32 table access; x8 should be the table base.
                // Hook the CRC function entry (0xffffffc0_086cb014 ADRP x8) and
                // the fault block start (0xffffffc0_086cb490) to compare x8.
                {
                    static mut CRC_ENTRY_HITS: u32 = 0;
                    static mut CRC_FAULT_HITS: u32 = 0;
                    let g = &*ptr::addr_of!(NPF_GUEST_CTX);
                    if *ptr::addr_of!(CRC_ENTRY_HITS) < 4
                       && pc == 0xFFFF_FFC0_086C_B014
                    {
                        *ptr::addr_of_mut!(CRC_ENTRY_HITS) += 1;
                        dual_puts(b"[dbg] CRC ENTRY hit=");
                        dual_puthex64(*ptr::addr_of!(CRC_ENTRY_HITS) as u64);
                        dual_puts(b" iter=");
                        dual_puthex64(iter);
                        dual_puts(b" x0=");
                        dual_puthex64(g[0]);
                        dual_puts(b" x1=");
                        dual_puthex64(g[1]);
                        dual_puts(b" x2=");
                        dual_puthex64(g[2]);
                        dual_puts(b" lr=");
                        dual_puthex64(g[30]);
                        dual_puts(b"\n");
                    }
                    if *ptr::addr_of!(CRC_FAULT_HITS) < 4
                       && pc == 0xFFFF_FFC0_086C_B490
                    {
                        *ptr::addr_of_mut!(CRC_FAULT_HITS) += 1;
                        dual_puts(b"[dbg] CRC FAULT-BLOCK hit=");
                        dual_puthex64(*ptr::addr_of!(CRC_FAULT_HITS) as u64);
                        dual_puts(b" iter=");
                        dual_puthex64(iter);
                        dual_puts(b" x8(table)=");
                        dual_puthex64(g[8]);
                        dual_puts(b" x10=");
                        dual_puthex64(g[10]);
                        dual_puts(b" x11=");
                        dual_puthex64(g[11]);
                        dual_puts(b" x12=");
                        dual_puthex64(g[12]);
                        dual_puts(b" lr=");
                        dual_puthex64(g[30]);
                        dual_puts(b"\n");
                    }
                }
                // Phase-C step 2: helper fdt_offset_ptr_ + jump-table dispatch
                // chain hooks. Multi-fire (counter, max 8 prints each) so the
                // SECOND helper invocation from path-0 (0x7d9e88c8 path =
                // FDT_BEGIN_NODE handler) is captured. Site layout:
                //   0x7d9e8780  helper entry
                //   0x7d9e87f4  helper fail (mov x8,xzr)
                //   0x7d9e87f8  helper return (mov x0,x8; ret)
                //   0x7d9e8800  helper success block
                //   0x7d9e8884  ADR X10,#+0x10 (jump-table base setup)
                //   0x7d9e8888  LDRB W11,[X9,X8] (table fetch)
                //   0x7d9e888c  ADD X10,X10,X11,LSL#2 (compute target)
                //   0x7d9e8890  BR X10
                //   0x7d9e88c8  jump-target #13 (FDT_BEGIN_NODE path)
                //   0x7d9e88d4  BL 0x7d9e8780 (second helper call)
                //   0x7d9e88d8  CBNZ X0,0x7d9e88bc (post-helper branch)
                {
                    static mut HELP_HITS: u32 = 0;
                    static mut RET_HITS: u32 = 0;
                    static mut OK_HITS: u32 = 0;
                    static mut FAIL_HITS: u32 = 0;
                    static mut JT_HITS: u32 = 0;
                    static mut PATH13_HITS: u32 = 0;
                    static mut BL2_HITS: u32 = 0;
                    static mut CBNZ_HITS: u32 = 0;
                    let g = &*ptr::addr_of!(NPF_GUEST_CTX);
                    if *ptr::addr_of!(HELP_HITS) < 8 && pc == 0x7D9E_8780 {
                        *ptr::addr_of_mut!(HELP_HITS) += 1;
                        dual_puts(b"[dbg] HELPER ENTRY hit=");
                        dual_puthex64(*ptr::addr_of!(HELP_HITS) as u64);
                        dual_puts(b" iter=");
                        dual_puthex64(iter);
                        dual_puts(b" x0=");
                        dual_puthex64(g[0]);
                        dual_puts(b" w1=");
                        dual_puthex64(g[1] & 0xFFFF_FFFF);
                        dual_puts(b" w2=");
                        dual_puthex64(g[2] & 0xFFFF_FFFF);
                        dual_puts(b" lr=");
                        dual_puthex64(g[30]);
                        dual_puts(b"\n");
                    }
                    if *ptr::addr_of!(FAIL_HITS) < 4 && pc == 0x7D9E_87F4 {
                        *ptr::addr_of_mut!(FAIL_HITS) += 1;
                        dual_puts(b"[dbg] HELPER FAIL hit=");
                        dual_puthex64(*ptr::addr_of!(FAIL_HITS) as u64);
                        dual_puts(b" iter=");
                        dual_puthex64(iter);
                        dual_puts(b"\n");
                    }
                    if *ptr::addr_of!(OK_HITS) < 8 && pc == 0x7D9E_8800 {
                        *ptr::addr_of_mut!(OK_HITS) += 1;
                        dual_puts(b"[dbg] HELPER OK hit=");
                        dual_puthex64(*ptr::addr_of!(OK_HITS) as u64);
                        dual_puts(b" iter=");
                        dual_puthex64(iter);
                        dual_puts(b" x0=");
                        dual_puthex64(g[0]);
                        dual_puts(b" x8=");
                        dual_puthex64(g[8]);
                        dual_puts(b" x1=");
                        dual_puthex64(g[1]);
                        dual_puts(b"\n");
                    }
                    if *ptr::addr_of!(RET_HITS) < 8 && pc == 0x7D9E_87F8 {
                        *ptr::addr_of_mut!(RET_HITS) += 1;
                        dual_puts(b"[dbg] HELPER RET hit=");
                        dual_puthex64(*ptr::addr_of!(RET_HITS) as u64);
                        dual_puts(b" iter=");
                        dual_puthex64(iter);
                        dual_puts(b" x8(ret)=");
                        dual_puthex64(g[8]);
                        dual_puts(b"\n");
                    }
                    // JUMP-TABLE BR x10 site: ADR x10 at 0x7d9e8884 is a
                    // block-start (post ADRP/ADD/ADD chain). The dispatcher
                    // may or may not start a block exactly here, but it's
                    // safe to hook -- if it's mid-block, no fire. Then the
                    // BR x10 lands at jump target; we also hook 0x7d9e88c8.
                    if *ptr::addr_of!(JT_HITS) < 8 && pc == 0x7D9E_8884 {
                        *ptr::addr_of_mut!(JT_HITS) += 1;
                        dual_puts(b"[dbg] JT-BASE hit=");
                        dual_puthex64(*ptr::addr_of!(JT_HITS) as u64);
                        dual_puts(b" iter=");
                        dual_puthex64(iter);
                        dual_puts(b" x8=");
                        dual_puthex64(g[8]);
                        dual_puts(b" x9=");
                        dual_puthex64(g[9]);
                        dual_puts(b" w20=");
                        dual_puthex64(g[20] & 0xFFFF_FFFF);
                        dual_puts(b" w23=");
                        dual_puthex64(g[23] & 0xFFFF_FFFF);
                        dual_puts(b"\n");
                    }
                    if *ptr::addr_of!(PATH13_HITS) < 8 && pc == 0x7D9E_88C8 {
                        *ptr::addr_of_mut!(PATH13_HITS) += 1;
                        dual_puts(b"[dbg] JT-PATH#13 (FDT_BEGIN_NODE) hit=");
                        dual_puthex64(*ptr::addr_of!(PATH13_HITS) as u64);
                        dual_puts(b" iter=");
                        dual_puthex64(iter);
                        dual_puts(b" x10=");
                        dual_puthex64(g[10]);
                        dual_puts(b" x11=");
                        dual_puthex64(g[11]);
                        dual_puts(b" x21=");
                        dual_puthex64(g[21]);
                        dual_puts(b" x22=");
                        dual_puthex64(g[22]);
                        dual_puts(b"\n");
                    }
                    if *ptr::addr_of!(BL2_HITS) < 8 && pc == 0x7D9E_88D4 {
                        *ptr::addr_of_mut!(BL2_HITS) += 1;
                        dual_puts(b"[dbg] BL2-PRE hit=");
                        dual_puthex64(*ptr::addr_of!(BL2_HITS) as u64);
                        dual_puts(b" iter=");
                        dual_puthex64(iter);
                        dual_puts(b" x0=");
                        dual_puthex64(g[0]);
                        dual_puts(b" w1=");
                        dual_puthex64(g[1] & 0xFFFF_FFFF);
                        dual_puts(b" w2=");
                        dual_puthex64(g[2] & 0xFFFF_FFFF);
                        dual_puts(b"\n");
                    }
                    if *ptr::addr_of!(CBNZ_HITS) < 8 && pc == 0x7D9E_88D8 {
                        *ptr::addr_of_mut!(CBNZ_HITS) += 1;
                        dual_puts(b"[dbg] CBNZ-POST hit=");
                        dual_puthex64(*ptr::addr_of!(CBNZ_HITS) as u64);
                        dual_puts(b" iter=");
                        dual_puthex64(iter);
                        dual_puts(b" x0(helper ret)=");
                        dual_puthex64(g[0]);
                        dual_puts(b"\n");
                    }
                }
                if !fired && pc == 0xFFFF_FFC0_099E_5824 {
                    *ptr::addr_of_mut!(PHASE_B_HOOK_FIRED) = true;
                    let g = &*ptr::addr_of!(NPF_GUEST_CTX);
                    let x20 = g[20];
                    let x19 = g[19];   // = dt_phys (saved at 0x19e578c: mov x19, x0)
                    let x0  = g[0];    // = fmt-string pointer for the panic
                    dual_puts(b"[dbg] PANIC HOOK reached image+0x19e5824 (setup_machine_fdt)\n");
                    dual_puts(b"[dbg]   x19(dt_phys)=");
                    dual_puthex64(x19);
                    dual_puts(b" x20(dt_virt)=");
                    dual_puthex64(x20);
                    dual_puts(b" x0(fmt)=");
                    dual_puthex64(x0);
                    dual_puts(b"\n");
                    if x20 == 0 {
                        dual_puts(b"[dbg]   => PATH A: fixmap_remap_fdt returned NULL\n");
                    } else {
                        dual_puts(b"[dbg]   => PATH B: early_init_dt_scan returned false\n");
                    }
                    dual_puts(b"[dbg]   iter=");
                    dual_puthex64(iter);
                    dual_puts(b"\n");
                }
            }

            // 1. Fetch: translate the (possibly virtual) PC to a guest PA.
            let fetch_pa = match npf_fetch_guest_pa(pc) {
                Some(pa) => {
                    fetch_abort_streak = 0; // a clean fetch breaks any abort streak
                    pa
                }
                None => {
                    // The fetch walk faulted; the walker recorded a pending
                    // instruction abort — vector to the EL1 handler and resume.
                    match inject_pending_fetch_abort(pc) {
                        Some(vector) => {
                            fetch_abort_streak += 1;
                            dual_puts(b"[exc] FETCH ABORT -> EL1 vector=");
                            dual_puthex64(vector);
                            dual_puts(b" elr(faulting pc)=");
                            dual_puthex64(pc);
                            dual_puts(b" streak=");
                            dual_puthex64(fetch_abort_streak as u64);
                            // Also print current VBAR_EL1 to distinguish
                            // "kernel never set VBAR" from "kernel set it
                            // but vector page is unmapped".
                            let g = &*ptr::addr_of!(NPF_GUEST_CTX);
                            const SR0: usize =
                                aether_translator::runtime::context::SYSREG_SLOT0;
                            let cur_vbar = g[SR0 + 6];
                            dual_puts(b" vbar=");
                            dual_puthex64(cur_vbar);
                            dual_puts(b"\n");
                            // C.3 MANDATORY: short-circuit fetch-abort loops
                            // when VBAR_EL1 is still 0. Without VBAR set the
                            // dispatcher will spin to FETCH_ABORT_STREAK_MAX
                            // (16) for no diagnostic value; fail fast at 4 so
                            // the upstream cause is more visible in the log.
                            if cur_vbar == 0 && fetch_abort_streak >= 4 {
                                dual_puts(b"[exc] *** FETCH-ABORT LOOP WITH VBAR_EL1=0 ***\n");
                                dual_puts(b"[exc]   Cause: a sync exception fired before the\n");
                                dual_puts(b"[exc]   kernel reached its earliest `msr vbar_el1,x5`\n");
                                dual_puts(b"[exc]   (image+0xf762e0). The fault that triggered the\n");
                                dual_puts(b"[exc]   vector is the real bug -- likely a translator\n");
                                dual_puts(b"[exc]   mistranslation upstream of the faulting block.\n");
                                exit_code = 3;
                                sum_pc = pc;
                                sum_iter = iter;
                                break;
                            }
                            if fetch_abort_streak >= FETCH_ABORT_STREAK_MAX {
                                dual_puts(b"[dbt] repeated fetch aborts (handler vector unfetchable / VBAR unset?) -- halting\n");
                                exit_code = 3;
                                sum_pc = pc;
                                sum_a = vector;
                                sum_b = fetch_abort_streak as u64;
                                sum_iter = iter;
                                break;
                            }
                            continue;
                        }
                        None => {
                            dual_puts(b"[dbt] fetch fault, no handler pc=");
                            dual_puthex64(pc);
                            dual_puts(b"\n");
                            exit_code = 7;
                            sum_pc = pc;
                            sum_iter = iter;
                            break;
                        }
                    }
                }
            };

            // 2. Read the guest instruction window (identity, page-clamped).
            let (host_va, len) = match read_guest_window_identity(fetch_pa, WINDOW_BYTES) {
                Some(w) => w,
                None => {
                    dual_puts(b"[dbt] fetch window out of range pc=");
                    dual_puthex64(pc);
                    dual_puts(b" fetch_pa=");
                    dual_puthex64(fetch_pa);
                    dual_puts(b"\n");
                    exit_code = 6;
                    sum_pc = pc;
                    sum_a = fetch_pa;
                    sum_iter = iter;
                    break;
                }
            };
            let bytes = core::slice::from_raw_parts(host_va, len);
            let insn0 = if bytes.len() >= 4 {
                u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
            } else {
                0
            };
            last_insn = insn0;
            // Phase-E: ring buffer of last N (pc, insn) for post-BRK forensics.
            // When the kernel hits a BUG_ON the actual BRK fires at a panic
            // trampoline; the executed branch that PUT us there is one entry
            // back in this ring. Dumping the last 32 distinct blocks reveals
            // which conditional check failed.
            const RING_LEN: usize = 32;
            static mut PC_RING: [u64; RING_LEN] = [0; RING_LEN];
            static mut INSN_RING: [u32; RING_LEN] = [0; RING_LEN];
            static mut RING_IDX: usize = 0;
            *ptr::addr_of_mut!(PC_RING[*ptr::addr_of!(RING_IDX) % RING_LEN]) = pc;
            *ptr::addr_of_mut!(INSN_RING[*ptr::addr_of!(RING_IDX) % RING_LEN]) = insn0;
            *ptr::addr_of_mut!(RING_IDX) = (*ptr::addr_of!(RING_IDX)).wrapping_add(1);
            if pc != prev_traced_pc {
                if loop_reps > 0 {
                    dual_puts(b"[dbt]   ^ looped ");
                    dual_puthex64(loop_reps);
                    dual_puts(b"x\n");
                    loop_reps = 0;
                }
                distinct_blocks += 1;
                // Track the pc range visited inside this heartbeat window so
                // a stuck-in-a-200-byte-function pattern shows up as a tiny
                // [hb_pc_min..hb_pc_max] span next heartbeat.
                if pc < hb_pc_min { hb_pc_min = pc; }
                if pc > hb_pc_max { hb_pc_max = pc; }
                if distinct_blocks <= DBT_TRACE_FIRST || iter % TRACE_PERIOD == 0 {
                    dual_puts(b"[dbt] #");
                    dual_puthex64(iter);
                    dual_puts(b" pc=");
                    dual_puthex64(pc);
                    dual_puts(b" insn=");
                    dual_puthex64(insn0 as u64);
                    if iter % TRACE_PERIOD == 0 {
                        // Heartbeat: also surface common loop-counter regs so a
                        // runaway loop (corrupted width/limit) is diagnosable.
                        let g = &*ptr::addr_of!(NPF_GUEST_CTX);
                        dual_puts(b" x9=");
                        dual_puthex64(g[9]);
                        dual_puts(b" x19=");
                        dual_puthex64(g[19]);
                        dual_puts(b" x20=");
                        dual_puthex64(g[20]);
                        // MMIO traffic counters: tells us whether the kernel
                        // has even reached the GIC / PL011 yet.
                        dual_puts(b" mmio[pl011=");
                        dual_puthex64(*ptr::addr_of!(crate::mmio_emu::MMIO_PL011_W) as u64);
                        dual_puts(b" gicd=");
                        dual_puthex64(*ptr::addr_of!(crate::mmio_emu::MMIO_GICD_W) as u64);
                        dual_puts(b" gicr=");
                        dual_puthex64(*ptr::addr_of!(crate::mmio_emu::MMIO_GICR_W) as u64);
                        dual_puts(b" other=");
                        dual_puthex64(*ptr::addr_of!(crate::mmio_emu::MMIO_OTHER_W) as u64);
                        dual_puts(b" last=");
                        dual_puthex64(*ptr::addr_of!(crate::mmio_emu::MMIO_LAST_ADDR));
                        dual_puts(b"] flt=");
                        dual_puthex64(*ptr::addr_of!(aether_translator::runtime::mmu::MMU_FAULT_COUNT) as u64);
                        dual_puts(b" far=");
                        dual_puthex64(*ptr::addr_of!(aether_translator::runtime::mmu::MMU_LAST_FAR));
                        dual_puts(b" esr=");
                        dual_puthex64(*ptr::addr_of!(aether_translator::runtime::mmu::MMU_LAST_ESR));
                        // Live VBAR_EL1 / SCTLR / TTBR1 snapshot — slot 6/0/2
                        // in the sysreg pool (SYSREG_SLOT0 == 101).
                        let g = &*ptr::addr_of!(NPF_GUEST_CTX);
                        const SR0: usize = aether_translator::runtime::context::SYSREG_SLOT0;
                        dual_puts(b" vbar=");
                        dual_puthex64(g[SR0 + 6]);
                        dual_puts(b" sctlr=");
                        dual_puthex64(g[SR0 + 0]);
                        dual_puts(b" ttbr1=");
                        dual_puthex64(g[SR0 + 2]);
                        dual_puts(b" 1st_far=");
                        dual_puthex64(*ptr::addr_of!(aether_translator::runtime::mmu::MMU_FIRST_FAR));
                        dual_puts(b" 1st_esr=");
                        dual_puthex64(*ptr::addr_of!(aether_translator::runtime::mmu::MMU_FIRST_ESR));
                        // Per-heartbeat deltas — the live signals for Task E:
                        //   dpl = new PL011 byte writes since last hb
                        //         (== chars printed in last 65536 blocks)
                        //   dist = distinct new PCs visited since last hb
                        //   pc_lo..pc_hi = pc span explored this window
                        let cur_pl011 = *ptr::addr_of!(crate::mmio_emu::MMIO_PL011_W);
                        let dpl = cur_pl011.wrapping_sub(hb_prev_pl011_w);
                        let dist = distinct_blocks.wrapping_sub(hb_prev_distinct);
                        dual_puts(b" dpl=");
                        dual_puthex64(dpl as u64);
                        dual_puts(b" dist=");
                        dual_puthex64(dist);
                        dual_puts(b" pc_lo=");
                        dual_puthex64(hb_pc_min);
                        dual_puts(b" pc_hi=");
                        dual_puthex64(hb_pc_max);
                        // Sysreg observability — catches unmodeled MRS/MSR loops
                        // (e.g. ID_AA64ISAR1_EL1 feature probes that we always
                        // read as 0). last_rd/last_wr are the live IDs (any MRS
                        // / MSR), unk_rd / unk_wr count MRS/MSR for regs we
                        // don't model at all (fallback `_ => 0`).
                        dual_puts(b" last_rd=");
                        dual_puthex64(*ptr::addr_of!(
                            aether_translator::runtime::sysreg_rt::SYSREG_LAST_READ_ID
                        ) as u64);
                        dual_puts(b" last_wr=");
                        dual_puthex64(*ptr::addr_of!(
                            aether_translator::runtime::sysreg_rt::SYSREG_LAST_WRITE_ID
                        ) as u64);
                        dual_puts(b" unk_rd=");
                        dual_puthex64(*ptr::addr_of!(
                            aether_translator::runtime::sysreg_rt::SYSREG_UNKNOWN_READS
                        ) as u64);
                        dual_puts(b"/");
                        dual_puthex64(*ptr::addr_of!(
                            aether_translator::runtime::sysreg_rt::SYSREG_LAST_UNKNOWN_READ_ID
                        ) as u64);
                        dual_puts(b" unk_wr=");
                        dual_puthex64(*ptr::addr_of!(
                            aether_translator::runtime::sysreg_rt::SYSREG_UNKNOWN_WRITES
                        ) as u64);
                        dual_puts(b"/");
                        dual_puthex64(*ptr::addr_of!(
                            aether_translator::runtime::sysreg_rt::SYSREG_LAST_UNKNOWN_WRITE_ID
                        ) as u64);
                        hb_prev_pl011_w = cur_pl011;
                        hb_prev_distinct = distinct_blocks;
                        hb_pc_min = u64::MAX;
                        hb_pc_max = 0;
                    }
                    dual_puts(b"\n");

                    // Fixmap-probe trace dump (one-shot). Fires on the first
                    // heartbeat after the walker has captured at least one
                    // high-VA walk. Prints per-level descriptors + status so
                    // we can compare against the kernel's expected
                    // dt_virt -> dt_phys mapping (status: 0x01 = ok,
                    // 0x80|kind<<4|level on fault; kind 1=Translation
                    // 2=AccessFlag 3=Permission).
                    if !fixmap_trace_dumped {
                        let n = *ptr::addr_of!(
                            aether_translator::runtime::mmu::MMU_TRACE_COUNT
                        ) as usize;
                        if n > 0 {
                            fixmap_trace_dumped = true;
                            let max = aether_translator::runtime::mmu::MMU_TRACE_MAX;
                            let take = if n < max { n } else { max };
                            let mut i = 0usize;
                            while i < take {
                                dual_puts(b"[mmu] FIXMAP-TRACE #");
                                dual_puthex64(i as u64);
                                dual_puts(b" va=");
                                dual_puthex64((*ptr::addr_of!(
                                    aether_translator::runtime::mmu::MMU_TRACE_VA
                                ))[i]);
                                dual_puts(b" ttbr=");
                                dual_puthex64((*ptr::addr_of!(
                                    aether_translator::runtime::mmu::MMU_TRACE_TTBR
                                ))[i]);
                                dual_puts(b" sl=");
                                dual_puthex64((*ptr::addr_of!(
                                    aether_translator::runtime::mmu::MMU_TRACE_START
                                ))[i] as u64);
                                dual_puts(b" d0=");
                                dual_puthex64((*ptr::addr_of!(
                                    aether_translator::runtime::mmu::MMU_TRACE_DESC0
                                ))[i]);
                                dual_puts(b" d1=");
                                dual_puthex64((*ptr::addr_of!(
                                    aether_translator::runtime::mmu::MMU_TRACE_DESC1
                                ))[i]);
                                dual_puts(b" d2=");
                                dual_puthex64((*ptr::addr_of!(
                                    aether_translator::runtime::mmu::MMU_TRACE_DESC2
                                ))[i]);
                                dual_puts(b" d3=");
                                dual_puthex64((*ptr::addr_of!(
                                    aether_translator::runtime::mmu::MMU_TRACE_DESC3
                                ))[i]);
                                dual_puts(b" pa=");
                                dual_puthex64((*ptr::addr_of!(
                                    aether_translator::runtime::mmu::MMU_TRACE_PA
                                ))[i]);
                                dual_puts(b" st=");
                                dual_puthex64((*ptr::addr_of!(
                                    aether_translator::runtime::mmu::MMU_TRACE_STATUS
                                ))[i] as u64);
                                dual_puts(b"\n");
                                i += 1;
                            }
                        }
                    }
                }
                prev_traced_pc = pc;
            } else {
                loop_reps += 1;
                // Same-PC heartbeat: a translated backward branch re-enters the
                // dispatcher at the same pc, so a bounded loop goes silent here.
                // Periodically surface the loop-counter regs (x10/x11 are the
                // __create_page_tables index/limit) so progress-vs-stuck is
                // visible: x10 climbing toward x11 = progressing; x10 frozen = a
                // loop-body instruction is mistranslated.
                if loop_reps == 0x1000 {
                    // One-shot full GPR dump the first time a block becomes a
                    // long self-loop: surfaces the loop-setup registers (limit,
                    // index, bases) so a mistranslated bound is traceable.
                    let g = &*ptr::addr_of!(NPF_GUEST_CTX);
                    dual_puts(b"[dbt] LOOP REGDUMP pc=");
                    dual_puthex64(pc);
                    dual_puts(b"\n");
                    let mut r = 0usize;
                    while r < 15 {
                        dual_puts(b"  x");
                        dual_puthex64(r as u64);
                        dual_puts(b"=");
                        dual_puthex64(g[r]);
                        dual_puts(b"\n");
                        r += 1;
                    }
                }
            }

            // 3. Cold-translate (idempotent: a cache hit returns Ok immediately).
            if aether_dbt_translate_block(pc, bytes) != AetherDbtResult::Ok {
                let (fpc, fw, fkind) = aether_dbt_last_failure();
                dual_puts(b"[dbt] TranslateFail pc=");
                dual_puthex64(fpc);
                dual_puts(b" word=");
                dual_puthex64(fw as u64);
                dual_puts(b" kind=");
                dual_puthex64(fkind as u64);
                dual_puts(b" (1=decode 2=lift 3=short 4=empty) iter=");
                dual_puthex64(iter);
                dual_puts(b"\n");
                exit_code = 1;
                sum_pc = fpc;
                sum_a = fw as u64;
                sum_b = fkind as u64;
                sum_iter = iter;
                break;
            }

            // 4. Safety-gate the emitted bytes (a UD2 = an unsupported op the
            //    grind must add; print the pc so it can be disassembled).
            let (bva, blen) = match aether_dbt_block_host_va(pc) {
                Some(v) => v,
                None => {
                    dual_puts(b"[dbt] host_va miss after Ok translate (BUG) pc=");
                    dual_puthex64(pc);
                    dual_puts(b"\n");
                    exit_code = 8;
                    sum_pc = pc;
                    sum_iter = iter;
                    break;
                }
            };
            if !block_is_safe_to_enter(bva, blen) {
                // BRK (ARMv8 BRK imm16 = 0xD4_20_xx_xx) — kernel BUG_BRK_IMM
                // class (0x800-0x8FF), KASAN traps, etc. Lifter lowers BRK to
                // UD2 (correct per spec — it must trap), but UD2 halts the
                // dispatcher. Instead inject a synchronous EL1 exception
                // (EC = 0x3C, BRK from current EL) so the kernel's BUG()
                // handler runs and tells us what assertion fired. Lets the
                // boot continue past kernel asserts of survivable severity.
                //
                // Encoding: 0xD4_20_iiii_LL00 -> mask 0xFFE0_001F == 0xD420_0000.
                let is_brk = (insn0 & 0xFFE0_001F) == 0xD420_0000;
                if is_brk {
                    let imm16 = ((insn0 >> 5) & 0xFFFF) as u64;
                    let esr = (0x3Cu64 << 26) | imm16;
                    dual_puts(b"[exc] BRK -> sync EL1 inject pc=");
                    dual_puthex64(pc);
                    dual_puts(b" imm16=");
                    dual_puthex64(imm16);
                    dual_puts(b" iter=");
                    dual_puthex64(iter);
                    dual_puts(b"\n");
                    // Phase-E: dump ring buffer of last RING_LEN distinct
                    // (pc, insn) on FIRST BRK only — so the trace doesn't
                    // flood when the kernel's panic handler emits more BRKs.
                    static mut BRK_DUMPED: bool = false;
                    if !*ptr::addr_of!(BRK_DUMPED) {
                        *ptr::addr_of_mut!(BRK_DUMPED) = true;
                        dual_puts(b"[exc] PRE-BRK ring (oldest first):\n");
                        let cur = *ptr::addr_of!(RING_IDX);
                        let mut i = 0usize;
                        while i < RING_LEN {
                            // oldest entry is the one we are about to overwrite
                            let slot = (cur + i) % RING_LEN;
                            let p = *ptr::addr_of!(PC_RING[slot]);
                            let ins = *ptr::addr_of!(INSN_RING[slot]);
                            if p != 0 {
                                dual_puts(b"  pc=");
                                dual_puthex64(p);
                                dual_puts(b" insn=");
                                dual_puthex64(ins as u64);
                                dual_puts(b"\n");
                            }
                            i += 1;
                        }
                        // Also dump key GPRs at the BRK so we can see
                        // x21/x26 (the corrupted PTE-looking values).
                        let g = &*ptr::addr_of!(NPF_GUEST_CTX);
                        dual_puts(b"[exc] GPRs at BRK:\n");
                        let mut r = 0usize;
                        while r < 31 {
                            dual_puts(b"  x");
                            dual_puthex64(r as u64);
                            dual_puts(b"=");
                            dual_puthex64(g[r]);
                            dual_puts(b"\n");
                            r += 1;
                        }
                    }
                    // Manually inject. The runtime exceptions::inject() wants
                    // a &mut [u64] ctx slice; NPF_GUEST_CTX is a sized array,
                    // turn it into a mutable slice.
                    let ctx_slice: &mut [u64] = &mut *ptr::addr_of_mut!(NPF_GUEST_CTX);
                    aether_translator::runtime::exceptions::inject(
                        ctx_slice,
                        aether_translator::runtime::exceptions::ExceptionKind::Sync,
                        esr,
                        0, // FAR_EL1 not architecturally set by BRK
                        false,
                    );
                    // Don't enter the UD2'd block; the dispatcher will pick
                    // up the new PC (VBAR + 0x200 for EL1h sync) next iter.
                    continue;
                }
                dual_puts(b"[dbt] block UNSAFE (UD2 / unsupported op) pc=");
                dual_puthex64(pc);
                dual_puts(b" iter=");
                dual_puthex64(iter);
                dual_puts(b"\n");
                exit_code = 2;
                sum_pc = pc;
                sum_a = insn0 as u64;
                sum_iter = iter;
                break;
            }

            // First-fault tracker: log block PC + far/esr the first time the
            // live dispatch fault count climbs above the M3/M4 proof baseline.
            let pre_flt = *ptr::addr_of!(aether_translator::runtime::mmu::MMU_FAULT_COUNT);

            // 5. Host-mode enter; PC + pending abort/IRQ/PSCI advance inside.
            match enter_translated_block_from_npf(pc) {
                Some(_next) => {
                    let post_flt = *ptr::addr_of!(aether_translator::runtime::mmu::MMU_FAULT_COUNT);
                    // Phase B: drop the baseline filter so the FIRST block whose
                    // fault count climbs is logged unconditionally. The proofs
                    // (M3 etc.) intentionally trigger faults and raise the
                    // baseline above 0, suppressing this print on the live
                    // path. To find what kernel code writes to PA 0x140040000
                    // we need the block PC regardless of how many proof
                    // faults preceded it.
                    let _ = live_flt_baseline;
                    if !first_live_flt_logged && post_flt > pre_flt {
                        first_live_flt_logged = true;
                        let far_now = *ptr::addr_of!(aether_translator::runtime::mmu::MMU_LAST_FAR);
                        let esr_now = *ptr::addr_of!(aether_translator::runtime::mmu::MMU_LAST_ESR);
                        dual_puts(b"[mmu] FIRST LIVE FAULT block_pc=");
                        dual_puthex64(pc);
                        dual_puts(b" first_insn=");
                        dual_puthex64(insn0 as u64);
                        dual_puts(b" far=");
                        dual_puthex64(far_now);
                        dual_puts(b" esr=");
                        dual_puthex64(esr_now);
                        dual_puts(b" iter=");
                        dual_puthex64(iter);
                        dual_puts(b"\n");
                        // PAGE TABLE DUMP for the failing VA. Walk TTBR1
                        // 3-level (4KiB granule, VA_BITS=39) and print L1/
                        // L2/L3 descriptor bytes so we can tell which level
                        // the walker is failing at (and why).
                        let ctx = &*ptr::addr_of!(NPF_GUEST_CTX);
                        const SR0: usize = aether_translator::runtime::context::SYSREG_SLOT0;
                        const SLOT_TTBR1: usize = 2;
                        let ttbr1 = ctx[SR0 + SLOT_TTBR1] & 0x0000_FFFF_FFFF_F000;
                        let l1_idx = (far_now >> 30) & 0x1FF;
                        let l2_idx = (far_now >> 21) & 0x1FF;
                        let l3_idx = (far_now >> 12) & 0x1FF;
                        dual_puts(b"[mmu]   TTBR1(masked)=");
                        dual_puthex64(ttbr1);
                        dual_puts(b" L1idx=");
                        dual_puthex64(l1_idx);
                        dual_puts(b" L2idx=");
                        dual_puthex64(l2_idx);
                        dual_puts(b" L3idx=");
                        dual_puthex64(l3_idx);
                        dual_puts(b"\n");
                        // Read L1 descriptor (8 bytes at ttbr1 + l1_idx*8).
                        if ttbr1 != 0 {
                            let l1_desc_pa = ttbr1 + l1_idx * 8;
                            let l1_desc = core::ptr::read_volatile(l1_desc_pa as *const u64);
                            dual_puts(b"[mmu]   L1 desc @ 0x");
                            dual_puthex64(l1_desc_pa);
                            dual_puts(b" = 0x");
                            dual_puthex64(l1_desc);
                            dual_puts(b"\n");
                            if l1_desc & 0b11 == 0b11 {
                                let l2_base = l1_desc & 0x0000_FFFF_FFFF_F000;
                                // Survey neighborhood: which L2 entries near
                                // l2_idx are populated? Find the upper edge of
                                // kernel mapping.
                                let lo = if l2_idx >= 4 { l2_idx - 4 } else { 0 };
                                let hi = core::cmp::min(l2_idx + 4, 511);
                                let mut i = lo;
                                while i <= hi {
                                    let p = l2_base + i * 8;
                                    let d = core::ptr::read_volatile(p as *const u64);
                                    dual_puts(b"[mmu]   L2[");
                                    dual_puthex64(i);
                                    dual_puts(b"]@0x");
                                    dual_puthex64(p);
                                    dual_puts(b"=0x");
                                    dual_puthex64(d);
                                    dual_puts(b"\n");
                                    i += 1;
                                }
                                let l2_desc_pa = l2_base + l2_idx * 8;
                                let l2_desc = core::ptr::read_volatile(l2_desc_pa as *const u64);
                                if l2_desc & 0b11 == 0b11 {
                                    let l3_base = l2_desc & 0x0000_FFFF_FFFF_F000;
                                    let l3_desc_pa = l3_base + l3_idx * 8;
                                    let l3_desc = core::ptr::read_volatile(l3_desc_pa as *const u64);
                                    dual_puts(b"[mmu]   L3 desc @ 0x");
                                    dual_puthex64(l3_desc_pa);
                                    dual_puts(b" = 0x");
                                    dual_puthex64(l3_desc);
                                    dual_puts(b"\n");
                                }
                            }
                        }
                    }
                    // NO-PROGRESS watchdog: next-PC == the PC just run, repeated
                    // NO_PROGRESS_LIMIT times (with no abort/IRQ/PSCI), is a stuck
                    // self-loop — report pc+insn and halt instead of spinning
                    // silently to MAX_ITERS. (CNTVCT advances every block, so a
                    // legitimate timed delay loop resets this well before the
                    // limit; only a truly unchanging spin trips it.)
                    let new_pc = (*ptr::addr_of!(NPF_GUEST_CTX))[NPF_PC_SLOT];
                    if new_pc == pc {
                        same_pc += 1;
                        if same_pc >= NO_PROGRESS_LIMIT {
                            dual_puts(b"[dbt] NO-PROGRESS (self-loop / cpu_park / panic spin) pc=");
                            dual_puthex64(pc);
                            dual_puts(b" insn=");
                            dual_puthex64(insn0 as u64);
                            dual_puts(b" repeats=");
                            dual_puthex64(same_pc);
                            dual_puts(b" iter=");
                            dual_puthex64(iter);
                            dual_puts(b"\n");
                            exit_code = 4;
                            sum_pc = pc;
                            sum_a = insn0 as u64;
                            sum_b = same_pc;
                            sum_iter = iter;
                            break;
                        }
                    } else {
                        same_pc = 0;
                    }
                }
                None => {
                    // Clean halt: PSCI SYSTEM_OFF / SYSTEM_RESET / CPU_OFF.
                    dual_puts(b"[x86] dispatch loop halt (PSCI/safety) at pc=");
                    dual_puthex64(pc);
                    dual_puts(b"\n");
                    exit_code = 5;
                    sum_pc = pc;
                    sum_iter = iter;
                    break;
                }
            }
        }

        // Final FIXMAP-TRACE dump before halt: ring-mode keeps the LAST 16
        // high-VA walks; on a silent-panic exit the freshest 16 walks should
        // include the fdt_check_header read whose result triggers the panic.
        {
            let n = *ptr::addr_of!(
                aether_translator::runtime::mmu::MMU_TRACE_COUNT
            ) as usize;
            let max = aether_translator::runtime::mmu::MMU_TRACE_MAX;
            let take = if n < max { n } else { max };
            // Phase B step 2: TLBI / flush counters.
            dual_puts(b"[mmu] tlbi_va_total=");
            dual_puthex64(*ptr::addr_of!(
                aether_translator::runtime::mmu::MMU_TLBI_VA_TOTAL
            ) as u64);
            dual_puts(b" tlbi_va_fixmap=");
            dual_puthex64(*ptr::addr_of!(
                aether_translator::runtime::mmu::MMU_TLBI_VA_FIXMAP
            ) as u64);
            dual_puts(b" first_fixmap_va=");
            dual_puthex64(*ptr::addr_of!(
                aether_translator::runtime::mmu::MMU_TLBI_VA_FIRST_FIXMAP
            ));
            dual_puts(b" flush_all_total=");
            dual_puthex64(*ptr::addr_of!(
                aether_translator::runtime::mmu::MMU_TLBI_FLUSH_ALL_TOTAL
            ) as u64);
            dual_puts(b"\n");
            dual_puts(b"[mmu] DTB-PA hits=");
            dual_puthex64(*ptr::addr_of!(
                aether_translator::runtime::mmu::MMU_PA_HIT_COUNT
            ) as u64);
            dual_puts(b" first_va=");
            dual_puthex64(*ptr::addr_of!(
                aether_translator::runtime::mmu::MMU_PA_HIT_FIRST_VA
            ));
            dual_puts(b"\n");
            dual_puts(b"[mmu] FINAL FIXMAP-TRACE (last ");
            dual_puthex64(take as u64);
            dual_puts(b" of ");
            dual_puthex64(n as u64);
            dual_puts(b" total)\n");
            let mut i = 0usize;
            while i < take {
                dual_puts(b"[mmu]   #");
                dual_puthex64(i as u64);
                dual_puts(b" va=");
                dual_puthex64((*ptr::addr_of!(
                    aether_translator::runtime::mmu::MMU_TRACE_VA
                ))[i]);
                dual_puts(b" pa=");
                dual_puthex64((*ptr::addr_of!(
                    aether_translator::runtime::mmu::MMU_TRACE_PA
                ))[i]);
                dual_puts(b" d1=");
                dual_puthex64((*ptr::addr_of!(
                    aether_translator::runtime::mmu::MMU_TRACE_DESC1
                ))[i]);
                dual_puts(b" d2=");
                dual_puthex64((*ptr::addr_of!(
                    aether_translator::runtime::mmu::MMU_TRACE_DESC2
                ))[i]);
                dual_puts(b" d3=");
                dual_puthex64((*ptr::addr_of!(
                    aether_translator::runtime::mmu::MMU_TRACE_DESC3
                ))[i]);
                dual_puts(b" st=");
                dual_puthex64((*ptr::addr_of!(
                    aether_translator::runtime::mmu::MMU_TRACE_STATUS
                ))[i] as u64);
                dual_puts(b"\n");
                i += 1;
            }
        }
        dual_puts(b"[x86] host-mode dispatch loop exited. Halting.\n");
        // Guaranteed-readable post-mortem: clear the framebuffer (which may have
        // scrolled the decisive line off-screen) and paint one concise box. COM1
        // already has the full inline trace above; this is the on-glass summary.
        paint_dispatch_summary(exit_code, sum_iter, last_pc, last_insn, sum_pc, sum_a, sum_b);
        halt();
    }
}

/// Repaint a clean, fixed-size post-mortem on the framebuffer after the live
/// dispatch loop halts. The streaming `[dbt]`/`[exc]` trace scrolls the decisive
/// line off the top on a heavy boot; this box always shows the final state.
///
/// `code` selects the one-line reason; `a`/`b` are the reason-specific payloads
/// captured at the break site (see the `exit_code` legend in the loop).
///
/// # Safety
/// Single-core EL2 post-halt context; touches only the framebuffer text console.
unsafe fn paint_dispatch_summary(
    code: u32,
    iters: u64,
    last_pc: u64,
    last_insn: u32,
    pc: u64,
    a: u64,
    b: u64,
) {
    unsafe {
        fb_text_clear();
        fb_text_puts(b"==== AETHER x86 DBT  --  dispatch halted ====\n\n");
        fb_text_puts(b"reached: live ARM64 kernel dispatch (DBT engine ran)\n");
        fb_text_puts(b"blocks executed (iter) = ");
        fb_text_puthex64(iters);
        fb_text_puts(b"\nlast pc   = ");
        fb_text_puthex64(last_pc);
        fb_text_puts(b"\nlast insn = ");
        fb_text_puthex64(last_insn as u64);
        fb_text_puts(b"\n\nreason: ");
        match code {
            0 => fb_text_puts(b"iteration cap reached (likely live spin)\n"),
            1 => {
                fb_text_puts(b"TRANSLATE-FAIL (unknown/undecodable insn)\n");
                fb_text_puts(b"  fail pc = ");
                fb_text_puthex64(pc);
                fb_text_puts(b"\n  word    = ");
                fb_text_puthex64(a);
                fb_text_puts(b"\n  kind    = ");
                fb_text_puthex64(b);
                fb_text_puts(b"  (1=decode 2=lift 3=short 4=empty)\n");
            }
            2 => {
                fb_text_puts(b"BLOCK UNSAFE (op lowered to UD2 -- unsupported)\n");
                fb_text_puts(b"  pc   = ");
                fb_text_puthex64(pc);
                fb_text_puts(b"\n  insn = ");
                fb_text_puthex64(a);
                fb_text_puts(b"\n");
            }
            3 => {
                fb_text_puts(b"FETCH-ABORT STORM (handler vector unfetchable)\n");
                fb_text_puts(b"  pc     = ");
                fb_text_puthex64(pc);
                fb_text_puts(b"\n  vector = ");
                fb_text_puthex64(a);
                fb_text_puts(b"\n  streak = ");
                fb_text_puthex64(b);
                fb_text_puts(b"\n");
            }
            4 => {
                fb_text_puts(b"NO-PROGRESS (self-loop / cpu_park / panic spin)\n");
                fb_text_puts(b"  pc      = ");
                fb_text_puthex64(pc);
                fb_text_puts(b"\n  insn    = ");
                fb_text_puthex64(a);
                fb_text_puts(b"\n  repeats = ");
                fb_text_puthex64(b);
                fb_text_puts(b"\n");
            }
            5 => {
                fb_text_puts(b"PSCI / safety halt (SYSTEM_OFF/RESET/CPU_OFF)\n");
                fb_text_puts(b"  pc = ");
                fb_text_puthex64(pc);
                fb_text_puts(b"\n");
            }
            6 => {
                fb_text_puts(b"FETCH WINDOW OUT-OF-RANGE (pc outside RAM span)\n");
                fb_text_puts(b"  pc       = ");
                fb_text_puthex64(pc);
                fb_text_puts(b"\n  fetch_pa = ");
                fb_text_puthex64(a);
                fb_text_puts(b"\n");
            }
            7 => {
                fb_text_puts(b"FETCH FAULT, no handler (VBAR unset?)\n");
                fb_text_puts(b"  pc = ");
                fb_text_puthex64(pc);
                fb_text_puts(b"\n");
            }
            _ => {
                fb_text_puts(b"host_va miss after Ok translate (INTERNAL BUG)\n");
                fb_text_puts(b"  pc = ");
                fb_text_puthex64(pc);
                fb_text_puts(b"\n");
            }
        }
        fb_text_puts(b"\n(full trace on COM1 serial)\n");
    }
}

/// M4b-3: inject the pending INSTRUCTION abort the fetch walker
/// ([`npf_fetch_guest_pa`]) recorded when a fetch faulted, using `pc` (the
/// faulting fetch VA) as ELR_EL1. Returns the EL1 handler PC to resume at, or
/// `None` if nothing was pending (should not happen — the caller only invokes
/// this after a fetch fault).
///
/// # Safety
/// Same single-core EL2 contract as [`enter_translated_block_from_npf`].
pub(crate) unsafe fn inject_pending_fetch_abort(pc: u64) -> Option<u64> {
    // SAFETY: single-core EL2 dispatch; ctx is the seeded NPF_GUEST_CTX base.
    unsafe {
        let ctx = npf_ctx_ptr();
        let ctx_slice = core::slice::from_raw_parts_mut(
            ctx,
            aether_translator::runtime::context::CTX_U64S,
        );
        ctx_slice[NPF_PC_SLOT] = pc; // ELR = the faulting fetch VA
        if aether_translator::runtime::exceptions::take_pending_abort(ctx_slice) {
            Some(ctx_slice[NPF_PC_SLOT]) // now the EL1 handler vector
        } else {
            None
        }
    }
}

#[inline(never)]
fn halt() -> ! {
    // RED screen-fill removed — fb_fill(FB_RED) wipes every diagnostic line
    // printed up to the halt, including the [svm] SHUTDOWN message and the
    // [vmexit] iter= ladder that tells us why we halted. Keep the 3 low
    // beeps so the user still has an audible cue, but leave the
    // framebuffer text intact so the post-mortem photo is readable.
    unsafe { beep_n(3, 440); }
    loop {
        unsafe { core::arch::asm!("cli; hlt", options(nomem, nostack)); }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FEX bring-up bridge
//
// Calls `init_dbt_integration_hv` with the statically reserved JIT + bump arenas.
// On a `--no-default-features` build (the default) the FEX library is stubbed
// and this returns `FexLibNotLinked` — that's expected and is not an error
// for the foundation gate; the message is just informational. On a build with
// `--features fex_linked` and libfex.a linked, this is the canonical entry
// point that satisfies the Ch52 hypervisor-side gate.
//
// Returns true iff FEX initialisation succeeded.
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(not(feature = "fex_linked"))]
unsafe fn try_init_fex() -> bool {
    // Default build: FEX library is stubbed. Avoid allocating the full 16 MiB
    // JIT cache + 8 MiB bump arena BSS regions that init_dbt_integration_hv's
    // validator requires. Log the skip and return false; the layered payload
    // path falls through to the foundation-gate HLT byte.
    unsafe {
        dual_puts(b"[fex] feature off - skipping init (build with --features fex_linked for Ch52)\n");
    }
    false
}

#[cfg(feature = "fex_linked")]
unsafe fn try_init_fex() -> bool {
    unsafe {
        // With the feature on, the full-sized JIT and bump arenas must exist.
        // The smoke-test BSS regions in this file are too small; production
        // builds wire init_dbt_integration_hv to UEFI-allocated memory ranges.
        // For the feature-on build we use aether_defaults() and rely on the
        // installer to have reserved that PA range in the EFI memory map.
        let cfg = DbtIntegrationConfig::aether_defaults();
        dual_puts(b"[fex] init_dbt_integration_hv()\n");
        let bindings  = &mut *ptr::addr_of_mut!(FEX_BINDINGS);
        let jit_cache = &mut *ptr::addr_of_mut!(FEX_JIT_CACHE);
        let queue     = &mut *ptr::addr_of_mut!(FEX_AOT_QUEUE);

        match init_dbt_integration_hv(&cfg, bindings, jit_cache, queue) {
            Ok(state) => {
                dual_puts(b"[fex] init OK phase=");
                dual_puthex64(state.phase as u64);
                dual_puts(b"\n");
                true
            }
            Err(HvDbtError::FexLibNotLinked) => {
                dual_puts(b"[fex] libfex.a not linked despite feature flag\n");
                false
            }
            Err(_) => {
                dual_puts(b"[fex] init FAILED (see HvDbtError variant)\n");
                false
            }
        }
    }
}
