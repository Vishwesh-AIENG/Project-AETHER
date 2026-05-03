// ch04: ARM64 page granule and address-space constants
//
// ARM64 supports three translation granules: 4KB, 16KB, and 64KB. The
// granule controls the page size, the number of page table levels, and how
// many bits of the address are used per level.
//
// AETHER uses the 4KB granule throughout. This is the most common choice
// on ARM64 systems (Linux, Android, and Windows-on-ARM all default to 4KB),
// it aligns with the choices made by Snapdragon X Elite's firmware, and it
// is the granule Google's Android Common Kernel expects.
//
// Reference: ARM ARM DDI0487 Section D5.2 (translation granule)
// Verified: linux-ref/arch/arm64/include/asm/pgtable-hwdef.h

// ─────────────────────────────────────────────────────────────────────────────
// 4KB granule — AETHER's chosen granule
// ─────────────────────────────────────────────────────────────────────────────

/// Page shift for the 4KB granule.
/// A page is 2^PAGE_SHIFT bytes = 4096 bytes.
pub const PAGE_SHIFT: u32 = 12;

/// Page size in bytes: 4096.
pub const PAGE_SIZE: u64 = 1 << PAGE_SHIFT;

/// Page mask: bitwise AND with this zeroes the lower PAGE_SHIFT bits,
/// giving the page-aligned base address of any address.
pub const PAGE_MASK: u64 = !(PAGE_SIZE - 1);

// ─────────────────────────────────────────────────────────────────────────────
// 4-level page table structure (4KB granule, 48-bit VA)
//
// With 4KB pages and 48-bit virtual addresses, the ARM64 translation walk is:
//
//  VA[47:39] → L0 (PGD) — 512 entries, each covers 512 GiB
//  VA[38:30] → L1 (PUD) — 512 entries, each covers   1 GiB
//  VA[29:21] → L2 (PMD) — 512 entries, each covers   2 MiB
//  VA[20:12] → L3 (PTE) — 512 entries, each covers   4 KiB
//  VA[11:0]  → page offset
//
// Stage 2 translation (Chapter 8) uses the same structure but with IPA
// (intermediate physical addresses) as input instead of VA.
//
// Verified: linux-ref/arch/arm64/include/asm/pgtable-hwdef.h
// ─────────────────────────────────────────────────────────────────────────────

/// Number of bits used per page table level with 4KB granule.
/// Each level uses 9 bits → 512 entries per table.
pub const PTRS_PER_LEVEL_SHIFT: u32 = 9;

/// Number of entries per page table at any level: 512.
pub const PTRS_PER_TABLE: u64 = 1 << PTRS_PER_LEVEL_SHIFT;

/// L2 (PMD) shift: bits [29:21] of the address select the L2 index.
pub const PMD_SHIFT: u32 = PAGE_SHIFT + PTRS_PER_LEVEL_SHIFT; // 21

/// L1 (PUD) shift: bits [38:30].
pub const PUD_SHIFT: u32 = PMD_SHIFT + PTRS_PER_LEVEL_SHIFT;  // 30

/// L0 (PGD) shift: bits [47:39].
pub const PGDIR_SHIFT: u32 = PUD_SHIFT + PTRS_PER_LEVEL_SHIFT; // 39

/// Size covered by one L2 entry: 2 MiB.
pub const PMD_SIZE: u64 = 1 << PMD_SHIFT;

/// Size covered by one L1 entry: 1 GiB.
pub const PUD_SIZE: u64 = 1 << PUD_SHIFT;

/// Size covered by one L0 entry: 512 GiB.
pub const PGDIR_SIZE: u64 = 1 << PGDIR_SHIFT;

// ─────────────────────────────────────────────────────────────────────────────
// Physical address space
//
// Snapdragon X Elite (and ARM64 in general) supports 48-bit physical
// addresses in the standard configuration. AETHER targets this width.
// 52-bit PA extensions exist but are not assumed.
// ─────────────────────────────────────────────────────────────────────────────

/// Physical address width AETHER assumes: 48 bits.
/// Machines with wider PA support will work — AETHER will simply not use
/// the upper bits.
pub const PA_BITS: u32 = 48;

/// Maximum physical address (exclusive upper bound): 2^48 = 256 TiB.
pub const PA_MAX: u64 = 1u64 << PA_BITS;

// ─────────────────────────────────────────────────────────────────────────────
// IPA (Intermediate Physical Address) space for guests
//
// AETHER grants each guest a 40-bit IPA space. This is large enough for
// any current ARM64 phone or laptop SoC's memory map and matches the
// T0SZ value AETHER will configure in VTCR_EL2 (Chapter 6).
//
// T0SZ = 64 - IPA_BITS = 64 - 40 = 24
// This means Stage 2 translation covers IPA addresses 0..2^40 (1 TiB).
//
// A Snapdragon X Elite laptop typically has at most 64 GiB physical RAM,
// so 1 TiB of IPA space gives comfortable room for device MMIO regions.
// ─────────────────────────────────────────────────────────────────────────────

/// IPA address space size for each guest: 40 bits = 1 TiB.
pub const IPA_BITS: u32 = 40;

/// VTCR_EL2.T0SZ value that produces a 40-bit IPA space.
/// T0SZ = 64 - IPA_BITS.
pub const VTCR_T0SZ_40BIT: u64 = (64 - IPA_BITS) as u64;

/// Maximum IPA value (exclusive): 2^40 = 1 TiB.
pub const IPA_MAX: u64 = 1u64 << IPA_BITS;

// ─────────────────────────────────────────────────────────────────────────────
// Alignment helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Round `addr` down to the nearest page boundary.
#[inline]
pub const fn page_align_down(addr: u64) -> u64 {
    addr & PAGE_MASK
}

/// Round `addr` up to the nearest page boundary.
/// Returns `addr` unchanged if already page-aligned.
#[inline]
pub const fn page_align_up(addr: u64) -> u64 {
    (addr + PAGE_SIZE - 1) & PAGE_MASK
}

/// Return true if `addr` is page-aligned.
#[inline]
pub const fn is_page_aligned(addr: u64) -> bool {
    (addr & (PAGE_SIZE - 1)) == 0
}

/// Return true if `size` is a non-zero multiple of the page size.
#[inline]
pub const fn is_page_sized(size: u64) -> bool {
    size > 0 && (size & (PAGE_SIZE - 1)) == 0
}

// ─────────────────────────────────────────────────────────────────────────────
// Compile-time checks
// ─────────────────────────────────────────────────────────────────────────────

const _: () = {
    assert!(PAGE_SIZE == 4096,         "PAGE_SIZE must be 4096 for 4KB granule");
    assert!(PMD_SHIFT  == 21,          "PMD_SHIFT  must be 21 with 4KB/9-bit levels");
    assert!(PUD_SHIFT  == 30,          "PUD_SHIFT  must be 30 with 4KB/9-bit levels");
    assert!(PGDIR_SHIFT == 39,         "PGDIR_SHIFT must be 39 with 4KB/9-bit levels");
    assert!(PMD_SIZE   == 2 * 1024 * 1024,  "PMD_SIZE must be 2 MiB");
    assert!(PUD_SIZE   == 1024 * 1024 * 1024, "PUD_SIZE must be 1 GiB");
    assert!(VTCR_T0SZ_40BIT == 24,    "T0SZ for 40-bit IPA must be 24");
};
