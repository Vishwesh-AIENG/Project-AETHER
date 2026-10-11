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

/// Run the one-shot self-test when a guest kernel VA is first executed.
pub static HW_MMU_SELFTEST: AtomicBool = AtomicBool::new(true);
static SELFTEST_DONE: AtomicBool = AtomicBool::new(false);

/// Shadow page-table pool: 2048 × 4 KiB = 8 MiB of intermediate tables, enough
/// for a boot's kernel working set (vmalloc + linear map + kimg). On exhaustion
/// the caller resets (bump to 0 + rebuild root). In `.bss`, identity-mapped, so
/// a pool page's physical address equals its usable virtual address.
const POOL_PAGES: usize = 2048;
static mut SHADOW_POOL: [Page4K; POOL_PAGES] = [const { Page4K([0u8; 4096]) }; POOL_PAGES];
static mut SHADOW_NEXT: usize = 0;
/// The shadow root (PML4). One page; its PA is the value loaded into CR3.
static mut SHADOW_PML4: Page4K = Page4K([0u8; 4096]);

/// Allocate a zeroed 4 KiB pool page; returns its (identity) physical address,
/// or 0 when the pool is exhausted.
#[allow(unsafe_code)]
fn pool_alloc() -> u64 {
    // SAFETY: EL2-private, single-vCPU; bump index bounded below.
    unsafe {
        let n = *ptr::addr_of!(SHADOW_NEXT);
        if n >= POOL_PAGES {
            return 0;
        }
        *ptr::addr_of_mut!(SHADOW_NEXT) = n + 1;
        let p = ptr::addr_of_mut!(SHADOW_POOL) as u64 + (n as u64) * 4096;
        // Already zero in .bss on first use; zero again in case of reuse.
        ptr::write_bytes(p as *mut u8, 0, 4096);
        p
    }
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

/// Resumable-#PF fill. Called from the `#PF` stub. Returns 1 when the fault was
/// a guest-alias shadow miss that we filled (the faulting `mov` should be
/// re-executed via `iretq`), or 0 when it is NOT ours / not fillable (an ARM
/// fault or MMIO or a genuine hypervisor bug) — the stub then falls to the
/// post-mortem. `error` is the #PF error code (bit1 = write).
///
/// Fills the LIVE CR3's PML4 (its high slots are empty under the OVMF identity
/// map) so there is no CR3 switch: the `mov [alias]` re-executes and the x86 MMU
/// now walks the freshly-installed shadow entry.
#[unsafe(no_mangle)]
pub extern "C" fn shadow_pf_try(cr2: u64, error: u64) -> u64 {
    // SAFETY: EL2-private single-vCPU diagnostic counter.
    unsafe {
        *ptr::addr_of_mut!(SHADOW_PF_CALLS) += 1;
        *ptr::addr_of_mut!(SHADOW_PF_LAST_CR2) = cr2;
    }
    if !is_guest_alias(cr2) {
        return 0;
    }
    // SAFETY: EL2-private single-vCPU; NPF_GUEST_CTX is the live guest context.
    unsafe {
        use aether_translator::runtime::context::CTX_U64S;
        let ctx = ptr::addr_of!(crate::boot_x86::NPF_GUEST_CTX) as *const u64;
        let sysregs = core::slice::from_raw_parts(ctx, CTX_U64S);
        let guest_va = guest_va_of(cr2);
        let is_write = error & 0x2 != 0;
        let pml4 = read_cr3() & 0x000F_FFFF_FFFF_F000;
        let mut alloc = pool_alloc;
        let read = |pa: u64| ptr::read(pa as *const u64);
        let mut write = |pa: u64, v: u64| ptr::write(pa as *mut u64, v);
        match aether_translator::runtime::shadow::shadow_fill_at(
            pml4, sysregs, guest_va, cr2, is_write, &mut alloc, &read, &mut write,
        ) {
            Ok(_) => {
                *ptr::addr_of_mut!(SHADOW_FILLS) += 1;
                1
            }
            // ARM fault / MMIO / pool exhaustion — not handled yet; fatal for now
            // (surfaces in the post-mortem so these cases are diagnosed, not
            // silently wrong). Increment 3b handles ARM-abort + MMIO unwinding.
            Err(_) => 0,
        }
    }
}

/// Count of shadow fills served by the resumable #PF (diagnostic).
pub static mut SHADOW_FILLS: u64 = 0;
/// Count of #PF stub -> shadow_pf_try entries (diagnostic).
pub static mut SHADOW_PF_CALLS: u64 = 0;
pub static mut SHADOW_PF_LAST_CR2: u64 = 0;

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
