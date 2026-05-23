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

#[allow(dead_code)] const FB_GREEN: u32 = 0x00_00FF00;
#[allow(dead_code)] const FB_RED:   u32 = 0x00_FF0000;
#[allow(dead_code)] const FB_AMBER: u32 = 0x00_FFAA00;
#[allow(dead_code)] const FB_BLUE:  u32 = 0x00_0000FF;

use crate::android_handoff::{
    prepare_android_handoff, AndroidHandoff, HandoffError,
};
use crate::boot::{BootContext, EfiSystemTable};
#[cfg(feature = "fex_linked")]
use crate::fex_integration::{
    init_fex_integration, AotPreTranslationQueue, FexError, FexHostBindings, FexIntegrationConfig,
    FexJitCache,
};
use crate::svm::{
    init_svm_foundation, vmrun, NptTable, NptTableEntry,
    SvmFoundationConfig, VmcbRegion, VMCB_SAVE_CR3,
    VMCB_EXIT_INFO_1, VMCB_EXIT_INFO_2,
};
use crate::vtx::{
    init_vtx_foundation, vmread, vmwrite, EptTable, EptTableEntry,
    VmcsRegion, VmxonRegion, VtxFoundationConfig, VMCS_GUEST_CR3,
};
use crate::x86_hw_validation::CpuVendor;

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
    unsafe { com1_puts(s); vga_puts(s); }
}

pub unsafe fn dual_puthex64(v: u64) {
    unsafe { com1_puthex64(v); vga_puthex64(v); }
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
static mut FEX_BINDINGS:  FexHostBindings        = FexHostBindings::new(0, 0);
#[cfg(feature = "fex_linked")]
static mut FEX_JIT_CACHE: FexJitCache            = FexJitCache::new(0, 0);
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
//   2. fex_dispatch::classify_intel → FexExitClass.
//   3. If FEX dispatch is armed (Android handoff completed), call
//      fex_dispatch::handle_vmexit and either VMRESUME (Reenter) or HALT.
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
        if crate::fex_dispatch::is_armed() {
            let exit = crate::fex_dispatch::classify_intel(basic, exit_qual, gpa);
            let action = crate::fex_dispatch::with_global_mut(|s| {
                crate::fex_dispatch::handle_vmexit(s, exit)
            });
            match action {
                crate::fex_dispatch::VmexitAction::Reenter => {
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
                crate::fex_dispatch::VmexitAction::Halt => {
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
    // ── 1. ExitBootServices (capture RSDP first; same as ARM path) ───────────
    let boot_ctx = unsafe {
        BootContext::from_uefi(
            image_handle as *mut _,
            system_table as *const EfiSystemTable,
        )
    };
    let _boot_result = unsafe { boot_ctx.run() };

    // ── 2. ConOut is dead. Switch to COM1 + VGA text mode + paint screen. ───
    unsafe {
        com1_init();
        vga_clear();
        dual_puts(b"\n[x86] ExitBootServices: OK\n");
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
    let handoff: Option<AndroidHandoff> = unsafe {
        match prepare_android_handoff() {
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
                dual_puthex64(h.fex_regs.x[0]);
                dual_puts(b"\n");
                Some(h)
            }
            Err(HandoffError::BootImgNotFound) => {
                dual_puts(b"[android] no boot.img staged at 0x80000000 - foundation gate\n");
                None
            }
            Err(_) => {
                dual_puts(b"[android] handoff prep failed - foundation gate fallback\n");
                None
            }
        }
    };

    let fex_ok = unsafe { try_init_fex() };

    unsafe {
        if fex_ok && handoff.is_some() {
            dual_puts(b"[x86] FEX ready + handoff prepared - Android dispatch armed\n");
            // Phase 5: arm the FEX dispatch state with the handoff's initial
            // ARM64 registers. host_vmexit_entry then drives the translate /
            // dispatch / classify loop on every exit.
            if let Some(ref h) = handoff {
                crate::fex_dispatch::arm_global(h.fex_regs);
            }
            // Phase 6: initialise the Android lifecycle scanner so PL011 DR
            // writes from the guest land in userspace_boot + app_compat
            // diagnostic state.
            crate::android_runtime::init_global();
        } else {
            // Fallback: foundation-gate payload — a HLT at GUEST_RAM_PA.
            let guest = ptr::addr_of_mut!(GUEST_RAM) as *mut u8;
            *guest = 0xF4;
        }
    }

    // ── 5. Branch on vendor ─────────────────────────────────────────────────
    let kernel_entry_pa = match &handoff {
        Some(h) if fex_ok => h.layout.kernel_pa,
        _                 => guest_ram_pa,
    };
    let extra_region: Option<(u64, u64)> = handoff.as_ref()
        .filter(|_| fex_ok)
        .map(|h| (h.region_pa, h.region_size));

    match vendor {
        Some(CpuVendor::Intel) => unsafe { boot_intel(
            vmxon_pa, vmcs_pa, ept_pml4_pa, guest_ram_pa,
            host_stack_top, host_rip, kernel_entry_pa, extra_region,
        ) },
        Some(CpuVendor::Amd) => unsafe { boot_amd(
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
            guest_ram_size:  4096,         // 4 KiB foundation-gate window
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

        dual_puts(b"[x86] VMLAUNCH...\n");
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
            guest_ram_size:  4096,
            mmio_base:       0,
            mmio_size:       0,
            guest_64bit:     true,
        };

        dual_puts(b"[x86] init_svm_foundation()...\n");
        let vmcb = &mut *(ptr::addr_of_mut!(VMCB_REGION));
        match init_svm_foundation(&cfg, vmcb) {
            Ok(state) => {
                dual_puts(b"[x86] init_svm_foundation: phase=");
                dual_puthex64(state.phase as u64);
                dual_puts(b" (NPT active)\n");
            }
            Err(_) => {
                dual_puts(b"[x86] init_svm_foundation FAILED. Check BIOS SVM.\n");
                halt();
            }
        }

        vmcb.write_u64(VMCB_SAVE_CR3, guest_cr3);

        // Phase 5b: AMD VMRUN is round-trip — control returns here on every
        // VMEXIT with host state restored from HSAVE. Loop: classify exit,
        // emulate (MMIO etc.), VMRUN again on Reenter. Break on Halt.
        //
        // The loop body deliberately re-reads VMCB fields after every VMRUN
        // because emulation may have updated them (e.g. EXITINFO2 for NPF).
        dual_puts(b"[x86] VMRUN dispatch loop start\n");
        const MAX_VMRUN_ITERATIONS: u64 = 1_000_000;
        let mut iter: u64 = 0;
        loop {
            vmrun(vmcb_pa);
            iter += 1;

            let exit_code = vmcb.exit_code();
            let exit_info_1 = vmcb.read_u64(VMCB_EXIT_INFO_1);
            let exit_info_2 = vmcb.read_u64(VMCB_EXIT_INFO_2);

            // Decide whether to drive the FEX dispatch path or just log.
            if !crate::fex_dispatch::is_armed() {
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

            // Armed: dispatch through FEX.
            let npf_gpa = exit_info_2;
            let exit = crate::fex_dispatch::classify_amd(exit_code, npf_gpa);
            let action = crate::fex_dispatch::with_global_mut(|s| {
                crate::fex_dispatch::handle_vmexit(s, exit)
            });
            match action {
                crate::fex_dispatch::VmexitAction::Reenter => {
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
                crate::fex_dispatch::VmexitAction::Halt => {
                    dual_puts(b"[fex] dispatch -> Halt (exit_code=");
                    dual_puthex64(exit_code);
                    dual_puts(b")\n");
                    break;
                }
            }
        }

        dual_puts(b"[x86] Hypervisor in SVM host mode. Halting.\n");
        halt();
    }
}

#[inline(never)]
fn halt() -> ! {
    loop {
        unsafe { core::arch::asm!("cli; hlt", options(nomem, nostack)); }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FEX bring-up bridge
//
// Calls `init_fex_integration` with the statically reserved JIT + bump arenas.
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
    // JIT cache + 8 MiB bump arena BSS regions that init_fex_integration's
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
        // builds wire init_fex_integration to UEFI-allocated memory ranges.
        // For the feature-on build we use aether_defaults() and rely on the
        // installer to have reserved that PA range in the EFI memory map.
        let cfg = FexIntegrationConfig::aether_defaults();
        dual_puts(b"[fex] init_fex_integration()\n");
        let bindings  = &mut *ptr::addr_of_mut!(FEX_BINDINGS);
        let jit_cache = &mut *ptr::addr_of_mut!(FEX_JIT_CACHE);
        let queue     = &mut *ptr::addr_of_mut!(FEX_AOT_QUEUE);

        match init_fex_integration(&cfg, bindings, jit_cache, queue) {
            Ok(state) => {
                dual_puts(b"[fex] init OK phase=");
                dual_puthex64(state.phase as u64);
                dual_puts(b"\n");
                true
            }
            Err(FexError::FexLibNotLinked) => {
                dual_puts(b"[fex] libfex.a not linked despite feature flag\n");
                false
            }
            Err(_) => {
                dual_puts(b"[fex] init FAILED (see FexError variant)\n");
                false
            }
        }
    }
}
