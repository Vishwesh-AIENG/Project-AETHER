//! ch66 phase 3b — hardware-MMU shadow paging (host mode), hypervisor side.
//!
//! Builds x86-64 shadow page tables that mirror the guest's ARM stage-1 mapping
//! (via `aether_translator::runtime::shadow::shadow_fill`) so translated code
//! can reach guest memory with a direct `mov [guest_va]`, the x86 CPU walking
//! the shadow, a miss taking a real host `#PF`.
//!
//! This file first lands the SELF-TEST (increment 2): it is bootable and
//! diagnosable, and proves the machinery (shadow_fill output + CR3 switch +
//! a guest VA becoming directly dereferenceable) WITHOUT touching the hot path.
//! The self-test is safe because the shadow root is a CLONE of the live CR3's
//! PML4 (so every hypervisor region — code, stack, ctx, JIT, IDT — stays mapped
//! exactly where it is) plus one extra guest KERNEL VA (TTBR1, `0xFFFF_FFC0…`),
//! which lands in a high PML4 slot the low identity map never uses, so it cannot
//! conflict. If anything is wrong the switch faults into the post-mortem IDT
//! (CR2/RIP on serial), never a silent triple-fault — provided the clone is
//! correct, which the self-test is precisely there to confirm.
//!
//! The full hot-path integration (direct-mov lowering for guest accesses) needs
//! the hypervisor relocated out of the guest's low user-VA space; this module
//! grows toward that. Everything here is gated behind `HW_MMU_SELFTEST` /
//! `HW_MMU_ENABLED` (default off) so the working software-TLB boot is untouched.
#![cfg(target_arch = "x86_64")]

use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::boot_x86::{dual_puthex64, dual_puts, Page4K};

/// Run the one-shot self-test when a guest kernel VA is first executed. Default
/// OFF so the committed normal boot is pristine (no shadow activity); flip to
/// true (or wire an env/boot arg) to re-run the on-HW validation. The resumable
/// #PF fill it exercises was PROVEN on a 2026-10-12 WHPX boot
/// (alias_now==ref_pa).
pub static HW_MMU_SELFTEST: AtomicBool = AtomicBool::new(false);
static SELFTEST_DONE: AtomicBool = AtomicBool::new(false);

/// Shadow page-table pool: 4096 × 4 KiB = 16 MiB of intermediate tables, enough
/// for a boot's kernel working set (vmalloc + linear map + kimg). On exhaustion
/// the caller resets (bump to 0 + rebuild root). In `.bss`, identity-mapped, so
/// a pool page's physical address equals its usable virtual address.
const POOL_PAGES: usize = 4096;
static mut SHADOW_POOL: [Page4K; POOL_PAGES] = [const { Page4K([0u8; 4096]) }; POOL_PAGES];
static mut SHADOW_NEXT: usize = 0;
/// The shadow root (PML4). One page; its PA is the value loaded into CR3.
static mut SHADOW_PML4: Page4K = Page4K([0u8; 4096]);

/// Free list of reclaimed pool pages (page indices), so dropped user subtrees
/// return their tables instead of leaking until the next full reset.
static mut FREE_LIST: [u16; POOL_PAGES] = [0; POOL_PAGES];
static mut FREE_TOP: usize = 0;

/// Allocate a zeroed 4 KiB pool page; returns its (identity) physical address,
/// or 0 when the pool is exhausted.
#[allow(unsafe_code)]
fn pool_alloc() -> u64 {
    // SAFETY: EL2-private, single-vCPU; indices bounded by POOL_PAGES.
    unsafe {
        let base = ptr::addr_of_mut!(SHADOW_POOL) as u64;
        let top = *ptr::addr_of!(FREE_TOP);
        let n = if top > 0 {
            *ptr::addr_of_mut!(FREE_TOP) = top - 1;
            (*ptr::addr_of!(FREE_LIST))[top - 1] as usize
        } else {
            let n = *ptr::addr_of!(SHADOW_NEXT);
            if n >= POOL_PAGES {
                return 0;
            }
            *ptr::addr_of_mut!(SHADOW_NEXT) = n + 1;
            n
        };
        let p = base + (n as u64) * 4096;
        // Already zero in .bss on first use; zero again in case of reuse.
        ptr::write_bytes(p as *mut u8, 0, 4096);
        p
    }
}

/// Return a pool page (by its physical address) to the free list.
#[allow(unsafe_code)]
fn pool_free(pa: u64) {
    // SAFETY: EL2-private, single-vCPU; `pa` came from pool_alloc.
    unsafe {
        let base = ptr::addr_of!(SHADOW_POOL) as u64;
        let idx = ((pa - base) / 4096) as usize;
        let top = *ptr::addr_of!(FREE_TOP);
        if idx < POOL_PAGES && top < POOL_PAGES {
            (*ptr::addr_of_mut!(FREE_LIST))[top] = idx as u16;
            *ptr::addr_of_mut!(FREE_TOP) = top + 1;
        }
    }
}

/// Pages still allocatable (bump headroom + free list).
#[allow(unsafe_code)]
fn pool_avail() -> usize {
    // SAFETY: EL2-private, single-vCPU.
    unsafe { POOL_PAGES - *ptr::addr_of!(SHADOW_NEXT) + *ptr::addr_of!(FREE_TOP) }
}

/// Free a whole user subtree given its PML4 entry (PDPT -> PD -> PT pages).
#[allow(unsafe_code)]
fn free_subtree(pml4e: u64) {
    const M: u64 = 0x000F_FFFF_FFFF_F000;
    if pml4e & 1 == 0 {
        return;
    }
    let pdpt = pml4e & M;
    // SAFETY: the subtree's tables are pool pages (identity-mapped).
    unsafe {
        for i in 0..512u64 {
            let pdpte = ptr::read((pdpt + i * 8) as *const u64);
            if pdpte & 1 == 0 {
                continue;
            }
            let pd = pdpte & M;
            for j in 0..512u64 {
                let pde = ptr::read((pd + j * 8) as *const u64);
                if pde & 1 != 0 {
                    pool_free(pde & M);
                }
            }
            pool_free(pd);
        }
    }
    pool_free(pdpt);
}

/// The PT covering `alias` under the subtree rooted at PML4 entry `pml4e`, or 0
/// when that 2 MiB region has no PT.
#[allow(unsafe_code)]
fn subtree_pt(pml4e: u64, alias: u64) -> u64 {
    const M: u64 = 0x000F_FFFF_FFFF_F000;
    if pml4e & 1 == 0 {
        return 0;
    }
    let mut table = pml4e & M;
    // SAFETY: pool pages, identity-mapped.
    unsafe {
        for shift in [30u32, 21] {
            let e = ptr::read((table + ((alias >> shift) & 0x1FF) * 8) as *const u64);
            if e & 1 == 0 {
                return 0;
            }
            table = e & M;
        }
    }
    table
}

#[allow(unsafe_code)]
fn read_cr3() -> u64 {
    let cr3: u64;
    // SAFETY: reading CR3 is a pure register read.
    unsafe { core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack)) };
    cr3
}

/// Load `cr3` (physical address of a PML4). Flushes the non-global TLB.
#[allow(unsafe_code)]
unsafe fn write_cr3(cr3: u64) {
    unsafe { core::arch::asm!("mov cr3, {}", in(reg) cr3, options(nostack)) };
}

/// Invalidate the TLB entry for one virtual address. REQUIRED after upgrading a
/// present shadow leaf (read-only → writable): the stale RO entry would else
/// re-fault the write forever. Harmless (cheap) after a first fill too.
#[allow(unsafe_code)]
unsafe fn invlpg(va: u64) {
    unsafe { core::arch::asm!("invlpg [{}]", in(reg) va, options(nostack)) };
}

/// Build the shadow root: clone every PML4 entry from the live CR3 (so the whole
/// hypervisor identity map — code, stack, ctx, JIT, IDT, the 4–8 GiB guest
/// window — stays mapped), returning the shadow PML4's physical address. Guest
/// kernel-VA mappings are then added into the (empty) high PML4 slots on demand.
#[allow(unsafe_code)]
unsafe fn build_shadow_root() -> u64 {
    let cur = read_cr3() & 0x000F_FFFF_FFFF_F000;
    let src = cur as *const u64;
    let dst = ptr::addr_of_mut!(SHADOW_PML4) as *mut u64;
    for i in 0..512 {
        unsafe { ptr::write(dst.add(i), ptr::read(src.add(i))) };
    }
    ptr::addr_of_mut!(SHADOW_PML4) as u64
}

/// Map one guest VA into the shadow tables (fills the PML4→PT path for it).
/// Returns the leaf host PA on success, or the ARM fault.
#[allow(unsafe_code)]
unsafe fn map_va(
    pml4_pa: u64,
    sysregs: &[u64],
    va: u64,
    is_write: bool,
) -> Result<u64, (aether_translator::runtime::mmu::FaultKind, u8)> {
    let mut alloc = pool_alloc;
    let read = |pa: u64| unsafe { ptr::read(pa as *const u64) };
    let mut write = |pa: u64, v: u64| unsafe { ptr::write(pa as *mut u64, v) };
    aether_translator::runtime::shadow::shadow_fill(
        pml4_pa, sysregs, va, is_write, &mut alloc, &read, &mut write,
    )
}

/// One-shot bootable self-test: map `va` (a known-mapped guest KERNEL VA) into a
/// clone-of-identity shadow, switch CR3 to it, read `*va` directly through the
/// x86 MMU, switch back, and confirm the value matches the software-walked PA.
/// Prints `[hwmmu] selftest …` to serial. `ctx` must point at the live guest
/// context (`CTX_U64S` slots); `va` must be a high (TTBR1) VA so it cannot
/// collide with the low identity map.
#[allow(unsafe_code)]
pub unsafe fn selftest(ctx: *const u64, va: u64) {
    use aether_translator::runtime::context::CTX_U64S;
    use aether_translator::runtime::mmu::walk;

    // SAFETY: EL2-private single-vCPU; `ctx` has CTX_U64S slots; the shadow is a
    // clone of the live CR3 (identity preserved) plus one high kernel-VA slot, so
    // the CR3 window keeps all hypervisor code/stack/IDT mapped.
    unsafe {
        let sysregs = core::slice::from_raw_parts(ctx, CTX_U64S);
        dual_puts(b"[hwmmu] selftest va=");
        dual_puthex64(va);

        // Reference: software-walk the VA to its guest PA and read it (the guest
        // window is identity-mapped, so the PA is directly readable now).
        let (ref_pa, _w) = match walk(sysregs, va, false) {
            Ok(x) => x,
            Err((_k, lvl)) => {
                dual_puts(b" SKIP(sw-walk-fault lvl=");
                dual_puthex64(lvl as u64);
                dual_puts(b")\n");
                return;
            }
        };
        let want = ptr::read_volatile(ref_pa as *const u64);

        // Build the shadow (clone identity) and add this one kernel VA.
        *ptr::addr_of_mut!(SHADOW_NEXT) = 0;
        let pml4 = build_shadow_root();
        if map_va(pml4, sysregs, va, false).is_err() {
            dual_puts(b" FAIL(shadow_fill)\n");
            return;
        }

        // Switch to the shadow CR3, read the VA directly through the x86 MMU,
        // switch back.
        let old = read_cr3();
        write_cr3(pml4);
        let got = ptr::read_volatile(va as *const u64);
        write_cr3(old);

        dual_puts(b" ref_pa=");
        dual_puthex64(ref_pa);
        dual_puts(b" want=");
        dual_puthex64(want);
        dual_puts(b" got=");
        dual_puthex64(got);
        if got == want {
            dual_puts(b" PASS\n");
        } else {
            dual_puts(b" FAIL(mismatch)\n");
            return;
        }

        // --- Increment 3a: resumable #PF on the LIVE CR3 via the gap alias ---
        // The 40-bit-mask alias lands in PML4[0x100] (empty under the firmware
        // identity map), so a direct read faults once; shadow_pf_try fills the
        // live CR3's gap slot from the guest tables; iretq re-runs the read, now
        // served by the x86 MMU. Proves the resumable #PF end-to-end.
        let alias = alias_of(va);
        // DIAG: is the alias already mapped in the LIVE CR3 (it should NOT be)?
        {
            let live = read_cr3() & 0x000F_FFFF_FFFF_F000;
            let rd = |pa: u64| ptr::read(pa as *const u64);
            let wa = aether_translator::runtime::shadow::x86_walk(live, alias, &rd);
            let wv = aether_translator::runtime::shadow::x86_walk(live, va, &rd);
            dual_puts(b"[hwmmu] diag live_pml4=");
            dual_puthex64(live);
            dual_puts(b" pml4[0x100]=");
            dual_puthex64(ptr::read((live + 0x100 * 8) as *const u64));
            dual_puts(b" alias_mapped=");
            dual_puthex64(match wa { Some((p, _)) => p, None => 0 });
            dual_puts(b" va_mapped=");
            dual_puthex64(match wv { Some((p, _)) => p, None => 0 });
            dual_puts(b"\n");
        }
        let got2 = ptr::read_volatile(alias as *const u64);
        // Ground truth: after the (faulting) read, the resumable #PF must have
        // mapped the alias to the guest PA. A re-walk of the LIVE CR3 confirms it
        // and the returned value matches. (The fills/calls counters are plain
        // static-mut reads the compiler may CSE across the volatile read, since
        // it can't see the #PF side effect — so this re-walk is authoritative.)
        let live = read_cr3() & 0x000F_FFFF_FFFF_F000;
        let rd = |pa: u64| ptr::read(pa as *const u64);
        let alias_now = match aether_translator::runtime::shadow::x86_walk(live, alias, &rd) {
            Some((p, _)) => p,
            None => 0,
        };
        dual_puts(b"[hwmmu] pf-fill alias=");
        dual_puthex64(alias);
        dual_puts(b" got=");
        dual_puthex64(got2);
        dual_puts(b" alias_now=");
        dual_puthex64(alias_now);
        dual_puts(b" pf_cr2=");
        dual_puthex64(ptr::read_volatile(ptr::addr_of!(SHADOW_PF_LAST_CR2)));
        if got2 == want && alias_now == ref_pa {
            dual_puts(b" PASS\n");
        } else {
            dual_puts(b" FAIL\n");
        }
    }
}

/// Gap base: guest VAs are accessed by translated code at `guest_va | GAP_BASE`
/// so guest low user-VAs don't collide with the hypervisor's low identity map.
/// User VAs (39-bit) alias into `[GAP_BASE, GAP_BASE + 512 GiB)`; kernel VAs
/// (`0xFFFF_FFC0…`) already have these bits set, so the OR leaves them at their
/// own high VA. Both land in high PML4 slots the low identity map never uses, so
/// the shadow lives in the LIVE CR3 with no switch.
pub const GAP_BASE: u64 = 0xFFFF_8000_0000_0000;
/// 40-bit guest-VA window: a 39-bit guest splits into user `[0, 512 GiB)` (bit39
/// clear) and kernel `[768 GiB, 1 TiB)` (bit39 set, i.e. `0xFFFF_FFC0…` low 40
/// bits). Both alias into `[GAP_BASE, GAP_BASE + 1 TiB)` = PML4[0x100], which
/// firmware leaves empty — UNLIKE the kernel's own PML4[0x1FF], which collides
/// with UEFI high-canonical mappings. `alias = GAP_BASE | (va & VA40_MASK)`.
const VA40_MASK: u64 = 0x0000_00FF_FFFF_FFFF;
const GAP_HI: u64 = GAP_BASE + (1u64 << 40); // + 1 TiB
/// Sign-extension to turn a bit39-set masked VA back into a kernel VA.
const KERN_SEXT: u64 = 0xFFFF_FF00_0000_0000;

/// The hardware-MMU access alias for a guest VA (what translated code dereferences
/// and what the shadow is indexed by).
#[inline]
pub fn alias_of(guest_va: u64) -> u64 {
    GAP_BASE | (guest_va & VA40_MASK)
}

/// Is `cr2` a guest-VA alias the hardware-MMU path owns (vs a real hypervisor
/// fault)? True only within the single 1 TiB gap window.
#[inline]
fn is_guest_alias(cr2: u64) -> bool {
    cr2 >= GAP_BASE && cr2 < GAP_HI
}

/// Reconstruct the guest VA from an alias `cr2`: strip the gap base to the 40-bit
/// window, then sign-extend if it is a kernel (bit39-set) VA.
#[inline]
fn guest_va_of(cr2: u64) -> u64 {
    let m = cr2 & VA40_MASK;
    if m & (1 << 39) != 0 {
        m | KERN_SEXT
    } else {
        m
    }
}

// A single `ret` in host_idt.rs: the ARM-abort redirect target. At a direct-mov
// fault the translated block's stack is clean, so `iretq` to this (with the
// frame's RSP) returns into `enter_host_block` → the dispatcher, which injects
// the pending abort.
unsafe extern "C" {
    fn host_block_abort_ret();
}

/// `#PF`-frame layout (u64 indices), matching the push order in host_idt.rs's
/// resumable #PF stub: r15@0 … rax@14, error@15, RIP@16, CS@17, RFLAGS@18,
/// RSP@19, SS@20.
const FRAME_RIP: usize = 16;
/// x86 GPR number (0=rax..15=r15) → frame u64 index. 255 = RSP (never a mov reg
/// here).
const REG_SLOT: [u8; 16] = [14, 12, 11, 13, 255, 8, 10, 9, 7, 6, 5, 4, 3, 2, 1, 0];

/// A decoded RAX-base `mov` (the alias deref the translator emits).
struct MovInfo {
    is_load: bool,
    size: u8,   // 1/2/4/8
    signed: bool,
    reg: u8,    // x86 GPR number (0..15)
    len: u8,    // instruction length in bytes
}

/// Decode the faulting alias-deref `mov` at `rip`. Only the exact RAX-base,
/// disp-0 integer forms the hardware-MMU lowering emits are recognised (loads:
/// mov r64/r32, movzx/movsx 8/16, movsxd 32; stores: mov sized) — anything else
/// returns None (→ fatal post-mortem, so an unexpected form is diagnosed).
#[allow(unsafe_code)]
unsafe fn decode_mov(rip: u64) -> Option<MovInfo> {
    let b = |i: u64| unsafe { ptr::read((rip + i) as *const u8) };
    let mut i = 0u64;
    let mut op66 = false;
    if b(i) == 0x66 {
        op66 = true;
        i += 1;
    }
    let mut rex = 0u8;
    if b(i) & 0xF0 == 0x40 {
        rex = b(i);
        i += 1;
    }
    let rex_w = rex & 0x08 != 0;
    let rex_r = rex & 0x04 != 0;
    let op = b(i);
    i += 1;
    let (is_load, size, signed, two_byte_op): (bool, u8, bool, bool) = match op {
        0x8B => (true, if rex_w { 8 } else { 4 }, false, false), // mov r,[rax]
        0x63 => (true, 4, true, false),                          // movsxd r64,m32
        0x89 => (false, if rex_w { 8 } else if op66 { 2 } else { 4 }, false, false), // mov [rax],r
        0x88 => (false, 1, false, false),                        // mov [rax],r8
        0x0F => {
            let op2 = b(i);
            i += 1;
            match op2 {
                0xB6 => (true, 1, false, true),  // movzx r64,m8
                0xB7 => (true, 2, false, true),  // movzx r64,m16
                0xBE => (true, 1, true, true),   // movsx r64,m8
                0xBF => (true, 2, true, true),   // movsx r64,m16
                _ => return None,
            }
        }
        _ => return None,
    };
    let _ = two_byte_op;
    let modrm = b(i);
    i += 1;
    // Require mod=00, rm=000 (base RAX, no SIB, no disp).
    if modrm & 0xC0 != 0x00 || modrm & 0x07 != 0x00 {
        return None;
    }
    let reg = ((modrm >> 3) & 0x07) | if rex_r { 8 } else { 0 };
    Some(MovInfo { is_load, size, signed, reg, len: i as u8 })
}

/// Resumable-#PF handler for the hardware-MMU path. `frame` points at the saved
/// GPRs (see FRAME_RIP). Returns 1 to `iretq` (possibly after patching the
/// frame's RIP / a dest GPR), or 0 to fall to the post-mortem.
///
/// Classifies the guest-alias fault by an ARM walk: RAM → fill the live CR3's
/// gap slot and resume (re-run the mov); MMIO → emulate via the soft-MMU helpers
/// and advance RIP past the mov; ARM fault → record the pending Data Abort and
/// redirect to the block-abort ret stub.
#[unsafe(no_mangle)]
pub extern "C" fn shadow_pf_try(cr2: u64, error: u64, frame: *mut u64) -> u64 {
    // SAFETY: EL2-private single-vCPU diagnostics.
    unsafe {
        *ptr::addr_of_mut!(SHADOW_PF_CALLS) += 1;
        *ptr::addr_of_mut!(SHADOW_PF_LAST_CR2) = cr2;
    }
    if !is_guest_alias(cr2) {
        return 0; // not ours — genuine hypervisor fault → post-mortem
    }
    // SAFETY: EL2-private single-vCPU; NPF_GUEST_CTX is the live guest context.
    unsafe {
        use aether_translator::runtime::context::{CTX_U64S, SYSREG_SLOT0};
        use aether_translator::runtime::mmu::{
            aether_mmu_resolve, aether_mmu_store, aether_mmu_xlate, data_abort_esr, pa_is_mmio,
            SLOT_PEND_ESR, SLOT_PEND_FAR, SLOT_PEND_PENDING,
        };
        let ctx = ptr::addr_of_mut!(crate::boot_x86::NPF_GUEST_CTX) as *mut u64;
        let sysregs = core::slice::from_raw_parts(ctx, CTX_U64S);
        let guest_va = guest_va_of(cr2);
        let is_write = error & 0x2 != 0;

        match aether_mmu_resolve(sysregs, guest_va, is_write) {
            Err((kind, level)) => {
                // ARM fault: record the pending Data Abort and redirect the block
                // to the abort ret-stub (clean stack at a direct-mov).
                *ctx.add(SYSREG_SLOT0 + SLOT_PEND_PENDING) = 1;
                *ctx.add(SYSREG_SLOT0 + SLOT_PEND_FAR) = guest_va;
                *ctx.add(SYSREG_SLOT0 + SLOT_PEND_ESR) = data_abort_esr(kind, level, is_write);
                *frame.add(FRAME_RIP) = (host_block_abort_ret as unsafe extern "C" fn()) as usize as u64;
                *ptr::addr_of_mut!(SHADOW_ABORTS) += 1;
                1
            }
            Ok(pa) if pa_is_mmio(pa) => {
                // MMIO: emulate via the soft-MMU helpers, do NOT fill the shadow,
                // advance RIP past the faulting mov.
                let rip = *frame.add(FRAME_RIP);
                let mi = match decode_mov(rip) {
                    Some(m) => m,
                    None => return 0, // unrecognised form → post-mortem
                };
                let slot = REG_SLOT[(mi.reg & 0xF) as usize];
                if slot == 255 {
                    return 0;
                }
                if mi.is_load {
                    let mpa = aether_mmu_xlate(ctx, guest_va, 0, mi.size as u64);
                    if mpa == 0 {
                        return 0; // fault during emulation
                    }
                    let raw = match mi.size {
                        1 => ptr::read(mpa as *const u8) as u64,
                        2 => ptr::read(mpa as *const u16) as u64,
                        4 => ptr::read(mpa as *const u32) as u64,
                        _ => ptr::read(mpa as *const u64),
                    };
                    let val = if mi.signed {
                        match mi.size {
                            1 => raw as u8 as i8 as i64 as u64,
                            2 => raw as u16 as i16 as i64 as u64,
                            4 => raw as u32 as i32 as i64 as u64,
                            _ => raw,
                        }
                    } else if mi.size == 4 {
                        raw & 0xFFFF_FFFF // mov r32 zero-extends
                    } else {
                        raw
                    };
                    *frame.add(slot as usize) = val;
                } else {
                    let rv = *frame.add(slot as usize);
                    let val = match mi.size {
                        1 => rv & 0xFF,
                        2 => rv & 0xFFFF,
                        4 => rv & 0xFFFF_FFFF,
                        _ => rv,
                    };
                    if aether_mmu_store(ctx, guest_va, mi.size as u64, val) == 0 {
                        // store helper signalled a fault (its ABI) — but RAM/MMIO
                        // writes return the PA/non-zero; 0 means a fault was
                        // recorded. Redirect to the abort stub.
                        *frame.add(FRAME_RIP) = (host_block_abort_ret as unsafe extern "C" fn()) as usize as u64;
                        return 1;
                    }
                }
                *frame.add(FRAME_RIP) = rip + mi.len as u64;
                *ptr::addr_of_mut!(SHADOW_MMIO) += 1;
                1
            }
            Ok(pa) => {
                // Plain RAM: map the alias -> resolved PA page base in the live
                // CR3 (writable = this access's intent; a write to a read-only
                // fill re-faults and upgrades). iretq re-runs the mov.
                // Pool guard: user-only resets don't reclaim pool pages, so when
                // the bump nears the cap do a full reset (reclaims everything)
                // before mapping — avoids pointing a leaf at pool page 0.
                if pool_avail() < 4 {
                    ucache_clear(); // reclaim parked user subtrees first
                    if pool_avail() < 4 {
                        *ptr::addr_of_mut!(SHADOW_GUARD_RESETS) += 1;
                        shadow_reset();
                    }
                }
                let pml4 = read_cr3() & 0x000F_FFFF_FFFF_F000;
                let mut alloc = pool_alloc;
                let read = |p: u64| ptr::read(p as *const u64);
                let mut write = |p: u64, v: u64| ptr::write(p as *mut u64, v);
                aether_translator::runtime::shadow::shadow_map_page(
                    pml4, cr2, pa & !0xFFF, is_write, &mut alloc, &read, &mut write,
                );
                // Flush the (possibly stale read-only) TLB entry for this alias so
                // a RO→RW upgrade takes effect; harmless on a first fill.
                invlpg(cr2);
                *ptr::addr_of_mut!(SHADOW_FILLS) += 1;
                1
            }
        }
    }
}

/// Count of shadow fills served by the resumable #PF (diagnostic).
pub static mut SHADOW_FILLS: u64 = 0;
/// Count of shadow resets (diagnostic).
pub static mut SHADOW_RESETS: u64 = 0;
/// Count of #PFs reflected to the guest as an ARM Data Abort (diagnostic).
pub static mut SHADOW_ABORTS: u64 = 0;
/// Count of MMIO accesses emulated from the #PF path (diagnostic).
pub static mut SHADOW_MMIO: u64 = 0;

/// Drop the whole gap shadow: clear the live CR3's PML4[0x100] (user) and
/// [0x101] (kernel) entries, reset the pool bump, and flush the TLB (CR3
/// reload). Registered as the translator's shadow-reset callback and invoked on
/// every TTBR/TCR/MAIR write and TLBI, so the shadow never goes stale. v1 is a
/// whole-shadow drop (a refault storm after a TTBR0 switch); a per-ASID / PCID
/// design is the follow-up optimisation.
#[unsafe(no_mangle)]
pub extern "C" fn shadow_reset() {
    // SAFETY: EL2-private single-vCPU; the gap PML4 slots belong to the shadow.
    unsafe {
        let pml4 = read_cr3() & 0x000F_FFFF_FFFF_F000;
        ptr::write((pml4 + 0x100 * 8) as *mut u64, 0); // user half
        ptr::write((pml4 + 0x101 * 8) as *mut u64, 0); // kernel half
        // Parked user subtrees live in the pool being reclaimed: drop them, and
        // label the (now empty) installed user half with the live TTBR0. The
        // whole pool is rebuilt from scratch, so the free list is discarded.
        *ptr::addr_of_mut!(UCACHE) = [(0, 0); UCACHE_N];
        *ptr::addr_of_mut!(UCACHE_NEXT) = 0;
        *ptr::addr_of_mut!(SHADOW_NEXT) = 0;
        *ptr::addr_of_mut!(FREE_TOP) = 0;
        *ptr::addr_of_mut!(UCUR_KEY) = live_ttbr0();
        *ptr::addr_of_mut!(SHADOW_RESETS) += 1;
        let c = read_cr3();
        write_cr3(c); // flush non-global TLB
    }
}

/// Per-address-space cache of user shadow subtrees: (TTBR0 value incl. ASID,
/// PML4[0x100] entry). A TTBR0 switch parks the outgoing subtree under its TTBR0
/// and reinstalls the incoming one's, so a context switch (or a SW_TTBR0_PAN
/// toggle back to the same table) does not re-fault the whole user working set.
/// Coherent because every way a cached translation can go stale is a guest TLBI
/// (Linux breaks-before-makes; ASID reuse is preceded by a TLBI on rollover):
/// any TLBI of a user VA drops all PARKED subtrees, any broad TLBI / full reset
/// drops everything. Evicted subtrees leak their pool pages until the next full
/// reset (the pool guard in `shadow_pf_try` triggers one).
const UCACHE_N: usize = 32;
static mut UCACHE: [(u64, u64); UCACHE_N] = [(0, 0); UCACHE_N];
static mut UCACHE_NEXT: usize = 0;
/// TTBR0 value whose subtree is currently installed in PML4[0x100].
static mut UCUR_KEY: u64 = 0;
/// Count of TTBR0 switches served from the cache (diagnostic).
pub static mut SHADOW_UCACHE_HITS: u64 = 0;
/// Count of user-half address-space switches (diagnostic).
pub static mut SHADOW_USER_SWITCHES: u64 = 0;
/// Count of full resets forced by pool exhaustion (diagnostic).
pub static mut SHADOW_GUARD_RESETS: u64 = 0;

/// The guest's live TTBR0_EL1 (incl. ASID) from the dispatcher's context.
#[allow(unsafe_code)]
fn live_ttbr0() -> u64 {
    use aether_translator::runtime::context::SYSREG_SLOT0;
    use aether_translator::runtime::mmu::SLOT_TTBR0;
    // SAFETY: EL2-private single-vCPU read of the live guest context.
    unsafe {
        let ctx = ptr::addr_of!(crate::boot_x86::NPF_GUEST_CTX) as *const u64;
        *ctx.add(SYSREG_SLOT0 + SLOT_TTBR0)
    }
}

/// Drop every parked user subtree (the installed one is untouched), returning
/// its tables to the pool.
#[allow(unsafe_code)]
unsafe fn ucache_clear() {
    unsafe {
        let cache = &mut *ptr::addr_of_mut!(UCACHE);
        for e in cache.iter_mut() {
            if e.1 != 0 {
                free_subtree(e.1);
            }
            *e = (0, 0);
        }
        *ptr::addr_of_mut!(UCACHE_NEXT) = 0;
    }
}

/// User-half switch (TTBR0 write): park the current PML4[0x100] subtree under the
/// outgoing TTBR0 and install the incoming TTBR0's cached subtree (or empty). The
/// kernel aliases (PML4[0x101]) are untouched. Reloads CR3 only when the entry
/// actually changes. The new TTBR0 is already in the guest context (the MSR
/// stores before this callback runs).
#[unsafe(no_mangle)]
pub extern "C" fn shadow_reset_user() {
    // SAFETY: EL2-private single-vCPU; PML4[0x100] belongs to the shadow.
    unsafe {
        let new_key = live_ttbr0();
        let old_key = *ptr::addr_of!(UCUR_KEY);
        if new_key == old_key {
            return; // same address space: the installed subtree is still right
        }
        let slot = (read_cr3() & 0x000F_FFFF_FFFF_F000) + 0x100 * 8;
        let cur = ptr::read(slot as *const u64);
        let cache = &mut *ptr::addr_of_mut!(UCACHE);
        // Park the outgoing subtree (replace its key's entry, else round-robin).
        if cur != 0 {
            match cache.iter().position(|e| e.0 == old_key && e.1 != 0) {
                Some(i) => {
                    if cache[i].1 != cur {
                        free_subtree(cache[i].1);
                    }
                    cache[i].1 = cur;
                }
                None => {
                    let i = *ptr::addr_of!(UCACHE_NEXT);
                    if cache[i].1 != 0 {
                        free_subtree(cache[i].1); // evict: reclaim its tables
                    }
                    cache[i] = (old_key, cur);
                    *ptr::addr_of_mut!(UCACHE_NEXT) = (i + 1) % UCACHE_N;
                }
            }
        }
        // Fetch the incoming one (taken out of the cache: it is now installed).
        let mut next = 0u64;
        if let Some(i) = cache.iter().position(|e| e.0 == new_key && e.1 != 0) {
            next = cache[i].1;
            cache[i] = (0, 0);
            *ptr::addr_of_mut!(SHADOW_UCACHE_HITS) += 1;
        }
        *ptr::addr_of_mut!(UCUR_KEY) = new_key;
        *ptr::addr_of_mut!(SHADOW_USER_SWITCHES) += 1;
        if next != cur {
            ptr::write(slot as *mut u64, next);
            let c = read_cr3();
            write_cr3(c); // drop the outgoing address space's TLB entries
        }
    }
}

/// Page-precise shadow invalidate for a guest `TLBI VA*` (`xt` = raw operand).
/// Clears every present leaf in the 2 MiB-aligned shadow page table that covers
/// the named page (INVLPG each), keeping the PT page attached so nothing leaks
/// from the pool. 2 MiB rather than 4 KiB because the guest may have mapped the
/// VA with an ARM block descriptor, which Linux invalidates with ONE TLBI per
/// block stride while our shadow holds 4 KiB leaves for it. Paging-structure
/// caches are covered by INVLPG (it drops all PSC entries for the PCID).
#[unsafe(no_mangle)]
pub extern "C" fn shadow_invalidate_va(xt: u64) {
    let va = aether_translator::runtime::mmu::tlbi_operand_va(xt);
    let alias = alias_of(va);
    // SAFETY: EL2-private single-vCPU; the gap subtree pages are pool pages
    // (identity-mapped), and only their leaf words are written.
    unsafe {
        *ptr::addr_of_mut!(SHADOW_INVAL_VAS) += 1;
        // A user-VA TLBI may name another address space's translation: clear
        // the same 2 MiB region in every PARKED user subtree too (not installed,
        // so no INVLPG: their TLB entries died with the CR3 reload that parked
        // them). The installed subtree is handled below like the kernel half.
        if (va >> 55) & 1 == 0 {
            for e in (*ptr::addr_of!(UCACHE)).iter() {
                let pt = subtree_pt(e.1, alias);
                if pt != 0 {
                    ptr::write_bytes(pt as *mut u8, 0, 4096);
                }
            }
        }
        let pml4 = read_cr3() & 0x000F_FFFF_FFFF_F000;
        let mut table = pml4;
        // Descend PML4 -> PDPT -> PD to the PT covering `alias` (stop if absent).
        for shift in [39u32, 30, 21] {
            let e = ptr::read((table + ((alias >> shift) & 0x1FF) * 8) as *const u64);
            if e & 1 == 0 {
                return; // nothing shadowed in this region
            }
            table = e & 0x000F_FFFF_FFFF_F000;
        }
        let base = alias & !0x1F_FFFF; // 2 MiB-aligned alias of the region
        for i in 0..512u64 {
            let slot = (table + i * 8) as *mut u64;
            if ptr::read(slot) & 1 != 0 {
                ptr::write(slot, 0);
                invlpg(base + (i << 12));
            }
        }
    }
}

/// Install the shadow machinery with the translator (once, at boot): the
/// shadow-reset callbacks. Enables HW-MMU invalidation coherence.
pub fn register() {
    aether_translator::runtime::mmu::register_shadow_reset(
        shadow_reset,
        shadow_reset_user,
        shadow_invalidate_va,
        shadow_ttbr1_written,
    );
}
/// TTBR1 table base the kernel half was filled under (ASID bits stripped).
static mut KERN_TTBR1_BASE: u64 = 0;
/// Count of kernel-half drops caused by a TTBR1 base change (diagnostic).
pub static mut SHADOW_TTBR1_RESETS: u64 = 0;

/// TTBR1 written (the new value is already in the guest context). If only the
/// ASID changed (SW_TTBR0_PAN does this on every uaccess) nothing is remapped;
/// if the table BASE changed (e.g. KPTI trampoline <-> swapper) the kernel
/// aliases may now be wrong, so the kernel half is dropped and its tables freed.
#[unsafe(no_mangle)]
pub extern "C" fn shadow_ttbr1_written() {
    use aether_translator::runtime::context::SYSREG_SLOT0;
    use aether_translator::runtime::mmu::SLOT_TTBR1;
    // SAFETY: EL2-private single-vCPU; PML4[0x101] belongs to the shadow.
    unsafe {
        let ctx = ptr::addr_of!(crate::boot_x86::NPF_GUEST_CTX) as *const u64;
        let mut base = *ctx.add(SYSREG_SLOT0 + SLOT_TTBR1) & 0x0000_FFFF_FFFF_FFFE;
        // KPTI flips TTBR1 between tramp_pg_dir and swapper_pg_dir (= tramp +
        // 0x2000) on every kernel entry/exit; the software MMU resolves the
        // trampoline base through the swapper snapshot, so kernel aliases are
        // identical under both — treat the pair as one address space.
        let snap = *ptr::addr_of!(aether_translator::runtime::mmu::KERNEL_PGD_SNAPSHOT);
        if snap != 0 && base == snap.wrapping_sub(0x2000) {
            base = snap;
        }
        if base == *ptr::addr_of!(KERN_TTBR1_BASE) {
            return;
        }
        *ptr::addr_of_mut!(KERN_TTBR1_BASE) = base;
        let slot = (read_cr3() & 0x000F_FFFF_FFFF_F000) + 0x101 * 8;
        let k = ptr::read(slot as *const u64);
        if k != 0 {
            ptr::write(slot as *mut u64, 0);
            free_subtree(k);
            let c = read_cr3();
            write_cr3(c);
        }
        *ptr::addr_of_mut!(SHADOW_TTBR1_RESETS) += 1;
    }
}

/// Count of page-precise TLBI invalidates (diagnostic).
pub static mut SHADOW_INVAL_VAS: u64 = 0;
/// Count of #PF stub -> shadow_pf_try entries (diagnostic).
pub static mut SHADOW_PF_CALLS: u64 = 0;
pub static mut SHADOW_PF_LAST_CR2: u64 = 0;

/// ch66 P3b: auto-enable the hardware-MMU path on the first guest kernel VA
/// (MMU guaranteed on). Default OFF — flip to true for an exploratory HW-MMU
/// boot. When it fires it registers the shadow-reset callback, turns on the
/// translator's direct-mov lowering, and flushes the block cache so every block
/// re-translates onto the hardware-MMU path.
pub static HW_MMU_AUTOENABLE: AtomicBool = AtomicBool::new(false);
static HW_MMU_ON: AtomicBool = AtomicBool::new(false);

#[allow(unsafe_code)]
pub unsafe fn maybe_enable_hw_mmu(pc: u64) {
    if !HW_MMU_AUTOENABLE.load(Ordering::Relaxed) || HW_MMU_ON.load(Ordering::Relaxed) {
        return;
    }
    if (pc >> 55) & 1 != 1 {
        return; // wait for the first kernel VA (guest MMU on)
    }
    HW_MMU_ON.store(true, Ordering::Relaxed);
    register(); // shadow-reset callback (coherence) BEFORE enabling
    // SAFETY: EL2-private single-vCPU; label the (empty) user half with the live
    // address space before any fill can happen.
    unsafe {
        *ptr::addr_of_mut!(UCUR_KEY) = live_ttbr0();
        use aether_translator::runtime::context::SYSREG_SLOT0;
        use aether_translator::runtime::mmu::SLOT_TTBR1;
        let ctx = ptr::addr_of!(crate::boot_x86::NPF_GUEST_CTX) as *const u64;
        *ptr::addr_of_mut!(KERN_TTBR1_BASE) = *ctx.add(SYSREG_SLOT0 + SLOT_TTBR1) & 0x0000_FFFF_FFFF_FFFE;
    }
    aether_translator::backend::lower_int::HW_MMU_ENABLED.store(true, Ordering::Relaxed);
    let _ = aether_translator::dbt::aether_dbt_invalidate_all(); // re-translate onto HW path
    // SAFETY: diagnostic print on the established path.
    unsafe {
        dual_puts(b"[hwmmu] ENABLED at pc=");
        dual_puthex64(pc);
        dual_puts(b"\n");
    }
}

/// Dispatch-loop hook: run the self-test once, the first time a guest KERNEL VA
/// (TTBR1, bit55 set) is about to execute with the MMU on. No-op afterwards and
/// when disabled.
#[allow(unsafe_code)]
pub unsafe fn maybe_selftest(ctx: *const u64, pc: u64) {
    if !HW_MMU_SELFTEST.load(Ordering::Relaxed) || SELFTEST_DONE.load(Ordering::Relaxed) {
        return;
    }
    if (pc >> 55) & 1 != 1 {
        return; // not a kernel VA
    }
    SELFTEST_DONE.store(true, Ordering::Relaxed);
    unsafe { selftest(ctx, pc) };
}
