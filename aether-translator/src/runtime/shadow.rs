//! ch66 phase 3b — shadow page-table builder for the hardware-MMU DBT path.
//!
//! Mirrors the guest's ARM stage-1 mapping for one VA into x86-64 shadow page
//! tables, so the x86 CPU's own MMU can translate a direct `mov [guest_va]` in
//! translated code. [`shadow_fill`] is the primitive the resumable `#PF` handler
//! calls on a shadow miss: it ARM-walks the VA (reusing [`crate::runtime::mmu::walk`]),
//! then creates/populates the PML4→PDPT→PD→PT path, leaf = host PA | P |
//! (RW iff the ARM leaf is writable). On an ARM fault it returns the
//! `(FaultKind, level)` so the caller can raise the precise Data Abort.
//!
//! Host-testable: `shadow_fill` takes closures for the x86 "physical" memory
//! (`read_phys`/`write_phys`) and page allocation, so a unit test can back the
//! x86 tables with synthetic memory and software-walk the result (see the test
//! module). The hypervisor backs the same closures with identity-mapped raw
//! pointer accesses and a reserved page pool.
//!
//! Parity with the software MMU: the shadow enforces exactly what
//! `mmu::finish_leaf` enforces (access flag + AP[2]/DBM writability); it does NOT
//! add EL0/EL1 or execute-never enforcement the software walker lacks.

use crate::runtime::mmu::{walk, FaultKind};

/// x86-64 page-table entry flags.
pub const X86_P: u64 = 1 << 0; // present
pub const X86_RW: u64 = 1 << 1; // writable
pub const X86_US: u64 = 1 << 2; // user/supervisor (0 = supervisor — ring-0 only)
pub const X86_NX: u64 = 1 << 63; // no-execute
/// Physical-frame field of an x86-64 PTE (bits [51:12]).
pub const X86_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// The four x86-64 4 KiB-granule table indices for `va` (PML4, PDPT, PD, PT).
#[inline]
fn x86_indices(va: u64) -> [usize; 4] {
    [
        ((va >> 39) & 0x1FF) as usize,
        ((va >> 30) & 0x1FF) as usize,
        ((va >> 21) & 0x1FF) as usize,
        ((va >> 12) & 0x1FF) as usize,
    ]
}

/// Populate the x86 shadow path for `va` from the guest's ARM tables.
///
/// `pml4_pa` is the shadow PML4's host physical address. `sysregs` is the guest
/// context's sysreg slice (TTBR0/1, TCR, SCTLR…). `alloc` returns a freshly
/// zeroed 4 KiB page's host PA for a new intermediate table. `read_phys` /
/// `write_phys` access an 8-byte-aligned host physical address. `va` must be the
/// canonical (post-TBI) address the CPU will present in CR2.
///
/// Returns the leaf host PA (page base | in-page offset of `va`) on success, or
/// the ARM `(FaultKind, level)` the guest walk produced.
pub fn shadow_fill(
    pml4_pa: u64,
    sysregs: &[u64],
    va: u64,
    is_write: bool,
    alloc: &mut dyn FnMut() -> u64,
    read_phys: &dyn Fn(u64) -> u64,
    write_phys: &mut dyn FnMut(u64, u64),
) -> Result<u64, (FaultKind, u8)> {
    // The guest's own walk decides reachability + permission, exactly as the
    // software-TLB path does. MMIO PAs fault out here (walk confines to the
    // window | MMIO; the caller leaves MMIO VAs unmapped so they re-fault into
    // the emulator) — shadow_fill is only asked to map plain RAM.
    let (pa, writable) = walk(sysregs, va, is_write)?;

    let idx = x86_indices(va);
    let mut table = pml4_pa;
    // Walk/create the three upper levels (PML4, PDPT, PD).
    for level in 0..3 {
        let entry_pa = table + (idx[level] as u64) * 8;
        let entry = read_phys(entry_pa);
        table = if entry & X86_P != 0 {
            entry & X86_ADDR_MASK
        } else {
            let next = alloc();
            // Upper levels: present + writable, supervisor (US=0). Per-page
            // permission lives on the leaf.
            write_phys(entry_pa, (next & X86_ADDR_MASK) | X86_P | X86_RW);
            next
        };
    }
    // Leaf (PT) entry.
    let leaf_pa = table + (idx[3] as u64) * 8;
    let mut pte = (pa & X86_ADDR_MASK) | X86_P;
    if writable {
        pte |= X86_RW;
    }
    write_phys(leaf_pa, pte);
    Ok(pa)
}

/// Software walk of x86 shadow tables (the inverse of [`shadow_fill`]), for
/// tests and diagnostics. Returns `(host_pa, writable)` or `None` if any level
/// is not present. 4 KiB leaves only (shadow_fill never creates large pages).
pub fn x86_walk(
    pml4_pa: u64,
    va: u64,
    read_phys: &dyn Fn(u64) -> u64,
) -> Option<(u64, bool)> {
    let idx = x86_indices(va);
    let mut table = pml4_pa;
    for level in 0..3 {
        let entry = read_phys(table + (idx[level] as u64) * 8);
        if entry & X86_P == 0 {
            return None;
        }
        table = entry & X86_ADDR_MASK;
    }
    let leaf = read_phys(table + (idx[3] as u64) * 8);
    if leaf & X86_P == 0 {
        return None;
    }
    let pa = (leaf & X86_ADDR_MASK) | (va & 0xFFF);
    Some((pa, leaf & X86_RW != 0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::context::{CTX_U64S, SYSREG_SLOT0};
    use crate::runtime::mmu::{
        aether_mmu_set_window, SLOT_SCTLR, SLOT_TCR, SLOT_TTBR0,
    };
    use std::collections::HashMap;

    const SCTLR_M: u64 = 1;
    const ADDR: u64 = 0x0000_FFFF_FFFF_F000;

    /// Serialize against every other test that touches the global MMU window /
    /// software TLB (shared with `mmu::tests`), and start from a clean TLB.
    fn serial() -> std::sync::MutexGuard<'static, ()> {
        let g = crate::runtime::mmu::MMU_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        crate::runtime::mmu::aether_mmu_flush_all();
        g
    }

    // Minimal ARM table builders (4 KiB granule, 4-level), in leaked host memory
    // so `mmu::walk` can read them via the window.
    #[allow(unsafe_code)]
    fn arm_page() -> (u64, &'static mut [u64; 512]) {
        // 4 KiB-aligned (walk() masks table bases to 4 KiB; an 8-aligned Box
        // would be mis-read). Leaked for a stable 'static address.
        let layout = std::alloc::Layout::from_size_align(4096, 4096).unwrap();
        // SAFETY: non-zero layout; we zero and own the allocation (leaked).
        let p = unsafe {
            let raw = std::alloc::alloc_zeroed(layout) as *mut [u64; 512];
            &mut *raw
        };
        (p.as_ptr() as u64, p)
    }
    fn table_desc(next: u64) -> u64 {
        (next & ADDR) | 0b11
    }
    fn leaf_desc(oa: u64, read_only: bool) -> u64 {
        let mut d = (oa & ADDR) | 0b11 | (1 << 10); // page + AF
        if read_only {
            d |= 1 << 7; // AP[2]
        }
        d
    }

    /// Build a 4-level identity-ish mapping VA->`pa` (RO optional) and return the
    /// L0 (TTBR0) base + the data-page host address, with the MMU window set to
    /// cover everything.
    fn map_one(va: u64, read_only: bool) -> (Vec<u64>, u64, u64) {
        let (l0_pa, l0) = arm_page();
        let (l1_pa, l1) = arm_page();
        let (l2_pa, l2) = arm_page();
        let (l3_pa, l3) = arm_page();
        let (data_pa, _data) = arm_page();
        l0[((va >> 39) & 0x1FF) as usize] = table_desc(l1_pa);
        l1[((va >> 30) & 0x1FF) as usize] = table_desc(l2_pa);
        l2[((va >> 21) & 0x1FF) as usize] = table_desc(l3_pa);
        l3[((va >> 12) & 0x1FF) as usize] = leaf_desc(data_pa, read_only);
        // Window must span the lowest..highest table/data page used.
        let lo = [l0_pa, l1_pa, l2_pa, l3_pa, data_pa]
            .into_iter()
            .min()
            .unwrap();
        let hi = [l0_pa, l1_pa, l2_pa, l3_pa, data_pa]
            .into_iter()
            .max()
            .unwrap();
        aether_mmu_set_window(lo, hi - lo + 4096);
        let mut ctx = vec![0u64; CTX_U64S];
        ctx[SYSREG_SLOT0 + SLOT_SCTLR] = SCTLR_M;
        ctx[SYSREG_SLOT0 + SLOT_TTBR0] = l0_pa;
        ctx[SYSREG_SLOT0 + SLOT_TCR] = 16; // T0SZ=16 -> 48-bit VA, 4-level
        (ctx, l0_pa, data_pa)
    }

    use core::cell::RefCell;

    /// Synthetic x86 "physical" memory for the shadow tables: a map from an
    /// 8-byte-aligned synthetic PA to a u64, plus a bump allocator. Shared by the
    /// read/write/alloc closures via a RefCell so they can all touch it.
    struct PhysMem {
        mem: RefCell<HashMap<u64, u64>>,
        next: RefCell<u64>,
    }
    impl PhysMem {
        fn new() -> Self {
            // Synthetic PA space well clear of any real pointer, 4 KiB-aligned.
            Self { mem: RefCell::new(HashMap::new()), next: RefCell::new(0x5000_0000_0000) }
        }
        fn alloc(&self) -> u64 {
            let mut n = self.next.borrow_mut();
            let p = *n;
            *n += 4096;
            p
        }
    }

    /// Run `shadow_fill` for `va` over a fresh `PhysMem`, then software-walk the
    /// result and return `(fill_result, x86_walk_result)`.
    fn fill_and_walk(
        pm: &PhysMem,
        pml4: u64,
        ctx: &[u64],
        va: u64,
        is_write: bool,
    ) -> (Result<u64, (FaultKind, u8)>, Option<(u64, bool)>) {
        let read = |pa: u64| *pm.mem.borrow().get(&pa).unwrap_or(&0);
        let mut alloc = || pm.alloc();
        let mut write = |pa: u64, v: u64| {
            pm.mem.borrow_mut().insert(pa, v);
        };
        let r = shadow_fill(pml4, ctx, va, is_write, &mut alloc, &read, &mut write);
        let w = x86_walk(pml4, va, &read);
        (r, w)
    }

    #[test]
    fn shadow_fill_matches_arm_walk_rw() {
        let _g = serial();
        let va = 0x0000_0042_0000_1234u64;
        let (ctx, _l0, _data) = map_one(va, false);
        let (arm_pa, arm_w) = walk(&ctx, va, false).expect("arm walk");
        assert!(arm_w, "page is RW");

        let pm = PhysMem::new();
        let pml4 = pm.alloc();
        let (r, w) = fill_and_walk(&pm, pml4, &ctx, va, false);
        assert_eq!(r, Ok(arm_pa), "shadow_fill returns the ARM leaf PA");
        assert_eq!(w, Some((arm_pa, true)), "x86 walk of the shadow matches ARM PA + writable");
    }

    #[test]
    fn shadow_fill_read_only_page_is_not_writable() {
        let _g = serial();
        let va = 0x0000_0001_0000_A000u64;
        let (ctx, _l0, _data) = map_one(va, true); // RO
        let (arm_pa, arm_w) = walk(&ctx, va, false).expect("arm walk (read)");
        assert!(!arm_w, "ARM leaf is read-only");

        let pm = PhysMem::new();
        let pml4 = pm.alloc();
        let (r, w) = fill_and_walk(&pm, pml4, &ctx, va, false);
        assert_eq!(r, Ok(arm_pa));
        assert_eq!(w, Some((arm_pa, false)), "shadow leaf must be present but NOT writable");
    }

    #[test]
    fn shadow_fill_unmapped_va_returns_arm_fault() {
        let _g = serial();
        let va = 0x0000_0042_0000_0000u64;
        let (ctx, _l0, _data) = map_one(va, false);
        // A VA in a different top-level slot is unmapped in the ARM tables.
        let bad = 0x0000_0043_0000_0000u64;
        let arm = walk(&ctx, bad, false);
        let arm_fault = arm.expect_err("ARM walk of the unmapped VA faults");

        let pm = PhysMem::new();
        let pml4 = pm.alloc();
        let (r, w) = fill_and_walk(&pm, pml4, &ctx, bad, false);
        assert_eq!(r.expect_err("shadow_fill faults"), arm_fault,
                   "shadow_fill propagates the exact ARM fault");
        assert_eq!(w, None, "nothing mapped for the faulting VA");
    }

    #[test]
    fn faulting_fill_allocates_no_x86_tables() {
        let _g = serial();
        // A fill whose guest VA faults in the ARM walk returns before touching
        // the x86 tables (walk() is the first thing shadow_fill does), so it
        // allocates no shadow pages.
        let va1 = 0x0000_0042_0000_1000u64;
        let (ctx, _l0, _d) = map_one(va1, false);
        let pm = PhysMem::new();
        let pml4 = pm.alloc();
        let (r1, w1) = fill_and_walk(&pm, pml4, &ctx, va1, false);
        assert!(r1.is_ok() && w1.is_some(), "mapped VA fills");
        let after_first = *pm.next.borrow();
        // A VA in a different top-level slot is unmapped in ARM -> fault.
        let va2 = 0x0000_0043_0000_1000u64;
        let (r2, w2) = fill_and_walk(&pm, pml4, &ctx, va2, false);
        assert!(r2.is_err(), "va2 is unmapped in ARM");
        assert_eq!(w2, None);
        assert_eq!(*pm.next.borrow(), after_first, "a faulting fill allocates no x86 tables");
    }
}
