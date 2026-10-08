// el2_mmu.rs — AETHER-owned EL2 stage-1 identity map (boot core).
//
// After ExitBootServices the boot core still translates EL2 addresses through
// the page tables UEFI built. Firmware allocates those wherever it likes — on
// QEMU `virt` that is low DRAM inside the guest's identity-mapped RAM window.
// Once Linux reuses those pages, the guest overwrites EL2's translation tables:
// EL2 can no longer fetch its own vectors and loops forever at VBAR_EL2+0x200
// (observed under QEMU, the third member of the "EL2 state in guest memory"
// class after the Stage 2 tables and the EL2 stack). EL2 must translate
// through tables it owns, placed in the hypervisor image (outside guest RAM).
//
// Layout: 4 KiB granule, T0SZ = 25 (39-bit VA), lookup starts at level 1, so
// one 512-entry table of 1 GiB block descriptors identity-maps PA 0..512 GiB:
//   GiB 0        Device-nGnRnE, execute-never (flash, GIC, UART, PCIe MMIO)
//   RAM GiBs     Normal Inner/Outer WB-RA-WA, Inner Shareable (DRAM, the
//                hypervisor image, Stage 2 tables) — only GiBs that the UEFI
//                memory map says contain RAM
//   all others   invalid: high MMIO (e.g. QEMU PCIe ECAM at 256 GiB) must never
//                be mapped Normal (speculative accesses to MMIO are unsafe)
// Source: ARM ARM DDI0487 D8.2 (VMSAv8-64 translation), D8.3 (descriptors),
// TCR_EL2 (non-VHE) / MAIR_EL2 field layouts.

/// MAIR_EL2: Attr0 = Normal WB RA WA (0xFF), Attr1 = Device-nGnRnE (0x00).
pub const MAIR_EL2_VALUE: u64 = 0xFF;
const ATTR_NORMAL: u64 = 0;
const ATTR_DEVICE: u64 = 1;

/// Number of 1 GiB entries in the level-1 table (T0SZ = 25 → 512 GiB).
pub const L1_ENTRIES: usize = 512;
const GIB: u64 = 1 << 30;

/// Level-1 entry for the GiB at index `i` (pure; unit-tested). `is_ram`:
/// the GiB overlaps RAM per the firmware memory map.
pub const fn l1_block(i: usize, is_ram: bool) -> u64 {
    let pa = (i as u64) * GIB;
    const VALID_BLOCK: u64 = 0b01;     // bits[1:0]: block descriptor
    const AP1_RES1: u64 = 1 << 6;      // AP[1] is RES1 in the EL2 regime; AP[2]=0 → RW
    const AF: u64 = 1 << 10;           // access flag: always set (no AF faults)
    const SH_INNER: u64 = 0b11 << 8;
    const XN: u64 = 1 << 54;
    if i == 0 {
        pa | VALID_BLOCK | (ATTR_DEVICE << 2) | AP1_RES1 | AF | XN
    } else if is_ram {
        pa | VALID_BLOCK | (ATTR_NORMAL << 2) | AP1_RES1 | AF | SH_INNER
    } else {
        0 // invalid
    }
}

/// TCR_EL2 (non-VHE) value for this map, given ID_AA64MMFR0_EL1.PARange.
pub const fn tcr_el2_value(parange: u64) -> u64 {
    const RES1: u64 = (1 << 31) | (1 << 23);
    const T0SZ: u64 = 25;
    const IRGN0_WBWA: u64 = 0b01 << 8;
    const ORGN0_WBWA: u64 = 0b01 << 10;
    const SH0_INNER: u64 = 0b11 << 12;
    const TG0_4K: u64 = 0b00 << 14;
    // PS[18:16]: physical address size; cap at 48-bit (0b101).
    let ps = if parange > 0b101 { 0b101 } else { parange };
    RES1 | T0SZ | IRGN0_WBWA | ORGN0_WBWA | SH0_INNER | TG0_4K | (ps << 16)
}

#[repr(C, align(4096))]
struct L1Table([u64; L1_ENTRIES]);

static mut EL2_L1: L1Table = L1Table([0; L1_ENTRIES]);

/// Physical address of the EL2 level-1 table (for the isolation guard).
pub fn el2_table_pa() -> u64 {
    core::ptr::addr_of!(EL2_L1) as u64
}

/// Build the table and switch the boot core's EL2 translation to it.
///
/// # Safety
/// Boot core only, at EL2 with the MMU on and UEFI's identity map active
/// (true right after ExitBootServices). The currently executing code, stack
/// and UART are identity-mapped in both the old and the new tables, so the
/// switch is seamless; TLBs are invalidated afterwards.
#[cfg(target_arch = "aarch64")]
/// Returns the SCTLR_EL2 value firmware left (for the boot log).
pub unsafe fn install_el2_identity_map(is_ram_gib: impl Fn(usize) -> bool) -> u64 {
    let table = core::ptr::addr_of_mut!(EL2_L1);
    for i in 0..L1_ENTRIES {
        // SAFETY: boot core, before any other user of EL2_L1.
        unsafe { (*table).0[i] = l1_block(i, is_ram_gib(i)) };
    }
    let mmfr0: u64;
    // SAFETY: ID register read at EL2.
    unsafe { core::arch::asm!("mrs {}, id_aa64mmfr0_el1", out(reg) mmfr0, options(nomem, nostack)) };
    let tcr = tcr_el2_value(mmfr0 & 0xF);
    let sctlr_before: u64;
    // SAFETY: see function contract.
    //
    // The switch runs with the EL2 MMU briefly OFF (this code is identity-
    // mapped, so PA == VA and execution simply continues):
    //  * Reprogramming MAIR_EL2 while UEFI's tables are live lets a fetch
    //    resolve UEFI's attribute index against the NEW MAIR — the code page
    //    can become Device memory, and instruction fetch from Device memory is
    //    a permission fault (EL2 then loops at VBAR_EL2+0x200).
    //  * SCTLR_EL2.WXN makes every writable page execute-never; this map is RW
    //    (image code, stack and data share pages), so WXN is cleared.
    // Table stores were made by cacheable writes and the walker is configured
    // cacheable (IRGN/ORGN WBWA), so it observes them after the DSB.
    unsafe {
        core::arch::asm!(
            "dsb  ish",
            "mrs  {s}, sctlr_el2",
            "bic  {t}, {s}, #1",          // M = 0
            "msr  sctlr_el2, {t}",
            "isb",
            "msr  mair_el2, {mair}",
            "msr  tcr_el2, {tcr}",
            "msr  ttbr0_el2, {ttbr}",
            "isb",
            "tlbi alle2",
            "dsb  ish",
            "isb",
            "bic  {t}, {s}, #(1 << 19)",  // WXN = 0
            "orr  {t}, {t}, #1",          // M = 1
            "msr  sctlr_el2, {t}",
            "isb",
            s    = out(reg) sctlr_before,
            t    = out(reg) _,
            mair = in(reg) MAIR_EL2_VALUE,
            tcr  = in(reg) tcr,
            ttbr = in(reg) table as u64,
            options(nostack),
        );
    }
    sctlr_before
}
/// Current TTBR0_EL2 base address (for the isolation guard).
#[cfg(target_arch = "aarch64")]
pub fn current_ttbr0_el2() -> u64 {
    let v: u64;
    // SAFETY: plain system-register read at EL2.
    unsafe { core::arch::asm!("mrs {}, ttbr0_el2", out(reg) v, options(nomem, nostack)) };
    v & 0x0000_FFFF_FFFF_F000
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mmio_gib_is_device_and_execute_never() {
        let d = l1_block(0, false);
        assert_eq!(l1_block(0, true), d, "GiB 0 is always MMIO");
        assert_eq!(d & 0b11, 0b01, "block descriptor");
        assert_eq!((d >> 2) & 0b111, ATTR_DEVICE);
        assert_ne!(d & (1 << 54), 0, "XN on MMIO");
        assert_ne!(d & (1 << 10), 0, "AF");
    }

    #[test]
    fn ram_gibs_are_normal_identity_and_executable() {
        // Guest window 0x4000_0000.. and the observed image GiB (0x1_3C6x_xxxx).
        for i in [1usize, 2, 5, 511] {
            let d = l1_block(i, true);
            assert_eq!(d & 0x0000_FFFF_C000_0000, (i as u64) << 30, "identity");
            assert_eq!((d >> 2) & 0b111, ATTR_NORMAL);
            assert_eq!(d & (1 << 54), 0, "executable");
            assert_eq!((d >> 8) & 0b11, 0b11, "inner shareable");
            assert_eq!(d & (1 << 7), 0, "AP[2]=0 read/write");
        }
        // Non-RAM GiBs (e.g. PCIe ECAM at 256 GiB) are left invalid.
        assert_eq!(l1_block(256, false), 0);
        // The hypervisor image observed at 0x1_3C65_A000 is covered.
        assert!((0x1_3C65_A000u64 >> 30) < L1_ENTRIES as u64);
    }

    #[test]
    fn tcr_fields() {
        let t = tcr_el2_value(0b101);
        assert_eq!(t & 0x3F, 25, "T0SZ 39-bit");
        assert_eq!((t >> 14) & 0b11, 0b00, "4K granule");
        assert_eq!((t >> 16) & 0b111, 0b101, "PS 48-bit");
        assert_ne!(t & (1 << 31), 0);
        assert_ne!(t & (1 << 23), 0);
        assert_eq!((tcr_el2_value(0b110) >> 16) & 0b111, 0b101, "PS capped");
        assert_eq!((tcr_el2_value(0b010) >> 16) & 0b111, 0b010, "PS follows PARange");
    }
}
