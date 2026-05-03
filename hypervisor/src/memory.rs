// ch08: Stage 2 Memory Architecture
//
// This module owns AETHER's Stage 2 page table manager — the hardware-enforced
// security boundary between each guest's IPA space and physical memory.
//
// Stage 2 translation (ARM ARM DDI0487 Section D5.5): when Android's CPU issues
// a load at VA, the MMU first walks Stage 1 (Android's own tables, rooted at
// TTBR0/1_EL1) to produce an IPA, then walks Stage 2 (AETHER's tables, rooted
// at VTTBR_EL2) to produce the true PA.  AETHER owns Stage 2 exclusively.
//
// CRITICAL — descriptor attribute encoding warning:
//   Stage 2 uses DIFFERENT bit fields than Stage 1. MemAttr[3:0] at bits [5:2]
//   uses ARM ARM Table D5-22 encoding (4-bit type), NOT an index into MAIR_EL1.
//   S2AP at bits [7:6] uses Table D5-21 encoding (not Stage 1 AP).
//   Getting either wrong produces silent wrong-type mappings.
//   This module imports pre-verified constants from `arm64::virt::stage2`
//   (sourced from linux-ref/arch/arm64/include/asm/{memory,kvm_pgtable}.h).
//
// Translation structure with VTCR_EL2 configured as T0SZ=24, SL0=1, 4KB granule:
//   IPA space: 40-bit (0 .. 1 TiB)
//   Starting level: L1 (concatenated pair of 4KB pages = 1024 entries)
//   L1 index: IPA[39:30] (10 bits → 1024 entries)
//   L2 index: IPA[29:21] ( 9 bits →  512 entries, each covers 2 MiB)
//   L3 index: IPA[20:12] ( 9 bits →  512 entries, each covers 4 KiB)
//
// TLB invalidation sequence (ARM ARM Section D5.10):
//   DSB ISH  →  TLBI VMALLS12E1IS  →  DSB ISH  →  ISB
//   All four instructions are mandatory; omitting any is a correctness bug.
//
// SMMU stream table:
//   ARM SMMU Architecture Specification v3 (IHI0070E), Section 6.3.
//   Every DMA-capable device on the SMMU must have an STE to restrict its
//   DMA to the guest's IPA→PA mapping. Devices without an STE default to
//   Abort (our table initialises to zero = all-Abort) which is safe.
//
// Primary references:
//   ARM ARM DDI0487 Section D5.2 (translation formats)
//   ARM ARM DDI0487 Section D5.5 (Stage 2 translation)
//   ARM ARM DDI0487 Table D5-22  (Stage 2 MemAttr encoding) — via stage2 module
//   ARM ARM DDI0487 Table D5-21  (Stage 2 S2AP encoding)    — via stage2 module
//   ARM ARM DDI0487 Section D5.10 (TLB maintenance)
//   ARM SMMU v3 IHI0070E Section 6.3 (Stream Table Entry format)
//   linux-ref/arch/arm64/kvm/mmu.c           (KVM Stage 2 reference)
//   linux-ref/drivers/iommu/arm/arm-smmu-v3/ (SMMU v3 driver reference)

use core::arch::asm;

use crate::arm64::barriers::{dsb_ish, dsb_ishst, isb};
use crate::arm64::paging::{
    page_align_up, PMD_SHIFT, PMD_SIZE, PUD_SHIFT, PAGE_SHIFT, PAGE_SIZE,
    VTCR_T0SZ_40BIT,
};
use crate::arm64::virt::stage2;

// ─────────────────────────────────────────────────────────────────────────────
// Output-address masks for Stage 2 descriptor fields
//
// Stage 2 block and page descriptors store the output physical address at
// specific bit ranges. These masks isolate only those bits so that descriptor
// type and attribute bits are never accidentally overwritten.
//
// Source: ARM ARM DDI0487 Figure D5-12 (4KB block/page descriptor layout)
// ─────────────────────────────────────────────────────────────────────────────

/// Bits [47:12] — page-aligned PA in a 4KB page descriptor.
const PA_MASK_4K: u64 = 0x0000_FFFF_FFFF_F000;
/// Bits [47:21] — 2MB-aligned PA in an L2 block descriptor.
const PA_MASK_2M: u64 = 0x0000_FFFF_FFE0_0000;
/// Bits [47:12] — page-aligned address of the next-level table in a table descriptor.
const TABLE_MASK: u64 = 0x0000_FFFF_FFFF_F000;

// ─────────────────────────────────────────────────────────────────────────────
// Error type
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapError {
    /// The page table page allocator ran out of memory.
    OutOfMemory,
    /// A mapping already exists for part of the requested range.
    AlreadyMapped,
    /// The requested range overflows 64-bit arithmetic.
    InvalidRange,
}

// ─────────────────────────────────────────────────────────────────────────────
// Memory mapping kind
//
// Controls the Stage 2 descriptor attribute bundle (MemAttr + S2AP + SH + XN).
// Deliberately a small enum — callers should not build raw attribute bitmasks.
// ─────────────────────────────────────────────────────────────────────────────

/// What kind of Stage 2 mapping to create.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapKind {
    /// Normal Write-Back Cacheable RAM, Inner Shareable, R+W, executable.
    /// Use for Android's code, heap, and stack regions.
    NormalRw,
    /// Normal Write-Back Cacheable RAM, Inner Shareable, read-only, executable.
    /// Use for read-only sections (kernel text after kernel init, DTB).
    NormalRo,
    /// Device nGnRE memory, Non-Shareable, R+W, execute-never.
    /// Use for MMIO ranges passed through to Android.
    DeviceRw,
}

// ─────────────────────────────────────────────────────────────────────────────
// Stage 2 bump page allocator
//
// Allocates zeroed 4KB pages from a contiguous physical memory region.
// Used exclusively during boot to supply page table pages before AETHER's
// full memory allocator (a later chapter) is available.
//
// Early-boot invariant: UEFI's identity map is still in effect at EL2, so
// physical addresses returned here are valid virtual addresses. This is
// documented as an invariant rather than enforced in code so that future
// chapters can replace this allocator without silent behaviour change.
// ─────────────────────────────────────────────────────────────────────────────

/// Bump allocator for Stage 2 page table pages.
///
/// Allocates zeroed 4KB pages from a contiguous physical range supplied by
/// the caller (typically `MemoryMap::largest_conventional()` from boot.rs).
pub struct BumpAllocator {
    cursor: u64,
    end: u64,
}

impl BumpAllocator {
    /// Create an allocator over the physical range [base, base+size).
    /// `base` is rounded up to the nearest 4KB boundary.
    pub fn new(base: u64, size: u64) -> Self {
        let cursor = page_align_up(base);
        let end = base.saturating_add(size);
        Self { cursor, end }
    }

    /// Allocate one zeroed 4KB page. Returns its physical address, or `None`
    /// when the region is exhausted.
    ///
    /// # Safety
    /// The physical range passed to `new()` must be writable and must not be
    /// aliased by any other live Rust reference. During early boot, the UEFI
    /// identity map guarantees that `pa as *mut u8` is a valid writable pointer.
    pub unsafe fn alloc_zeroed_page(&mut self) -> Option<u64> {
        let pa = self.cursor;
        let next = pa.checked_add(PAGE_SIZE)?;
        if next > self.end {
            return None;
        }
        self.cursor = next;
        // Zero the page via the UEFI identity map (phys == virt in early boot).
        unsafe { core::ptr::write_bytes(pa as *mut u8, 0, PAGE_SIZE as usize) };
        Some(pa)
    }

    /// Allocate `n` consecutive zeroed 4KB pages with the given byte alignment.
    /// `align_bytes` must be a power of two and ≥ PAGE_SIZE.
    /// Returns the physical address of the first page, or `None` on failure.
    ///
    /// # Safety
    /// Same preconditions as `alloc_zeroed_page`.
    pub unsafe fn alloc_zeroed_pages_aligned(
        &mut self,
        n: u64,
        align_bytes: u64,
    ) -> Option<u64> {
        let base = (self.cursor.checked_add(align_bytes - 1)?) & !(align_bytes - 1);
        let total = n.checked_mul(PAGE_SIZE)?;
        let new_cursor = base.checked_add(total)?;
        if new_cursor > self.end {
            return None;
        }
        self.cursor = new_cursor;
        unsafe { core::ptr::write_bytes(base as *mut u8, 0, total as usize) };
        Some(base)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Stage 2 page table manager
//
// Manages the concatenated L1 root table and all sub-tables for one guest
// partition. Provides a single `map_range` entry point that selects 2MB blocks
// or 4KB pages as appropriate.
// ─────────────────────────────────────────────────────────────────────────────

/// AETHER's Stage 2 page table manager for one guest partition.
///
/// With T0SZ=24 (40-bit IPA) and 4KB granule, the root is a concatenated pair
/// of 4KB pages forming a 1024-entry L1 table (covers 0 .. 1 TiB IPA).
/// VTTBR_EL2 must point to the first page of this concatenated pair, and the
/// pair must be 8KiB-aligned (2^13 bytes — required by the ARM architecture
/// for the T0SZ/SL0 combination used by AETHER).
pub struct Stage2Tables {
    /// Physical address of the 8KiB-aligned concatenated L1 root (two pages).
    root_pa: u64,
}

impl Stage2Tables {
    /// Allocate and zero the concatenated L1 root table from `alloc`.
    ///
    /// Allocates two consecutive 4KB pages at 8KiB alignment. The returned
    /// `root_pa` must be passed to `virt::configure_el2_virt()`.
    ///
    /// # Safety
    /// `alloc` must cover writable, non-aliased physical memory.
    pub unsafe fn new(alloc: &mut BumpAllocator) -> Option<Self> {
        // 8KiB alignment is mandatory for the concatenated L1 root.
        // ARM ARM DDI0487: VTTBR_EL2.BADDR alignment requirement for
        // T0SZ=24, SL0=1 (starting level 1) = 2^(IPA_BITS − 9*levels) =
        // 2^(40 − 27) = 2^13 = 8KiB.
        let root_pa = unsafe { alloc.alloc_zeroed_pages_aligned(2, 8192)? };
        Some(Self { root_pa })
    }

    /// Physical address of the Stage 2 root table.
    /// Pass this to `virt::configure_el2_virt()` and `vttbr_el2::build()`.
    #[inline]
    pub fn root_pa(&self) -> u64 {
        self.root_pa
    }

    /// Map the IPA range [ipa_start, ipa_start+size) to PA range
    /// [pa_start, pa_start+size) with the given mapping kind.
    ///
    /// Uses 2MB block entries where both IPA and PA are 2MB-aligned and the
    /// remaining span is ≥ 2MB. Falls back to 4KB pages elsewhere.
    ///
    /// Does NOT flush TLBs after mapping — call `tlb_flush_s1s2_vmid()` once
    /// all mappings for a guest are in place (one flush is cheaper than many).
    ///
    /// # Safety
    /// - Must be called from EL2 during single-threaded early boot.
    /// - `alloc` must provide writable, non-aliased physical pages.
    /// - The IPA range must not overlap any existing mapping in this table.
    pub unsafe fn map_range(
        &self,
        ipa_start: u64,
        pa_start: u64,
        size: u64,
        kind: MapKind,
        alloc: &mut BumpAllocator,
    ) -> Result<(), MapError> {
        if size == 0 {
            return Ok(());
        }
        let ipa_end = ipa_start.checked_add(size).ok_or(MapError::InvalidRange)?;
        let mut ipa = ipa_start;
        let mut pa = pa_start;

        while ipa < ipa_end {
            let remaining = ipa_end - ipa;
            let ipa_block_aligned = (ipa & (PMD_SIZE - 1)) == 0;
            let pa_block_aligned = (pa & (PMD_SIZE - 1)) == 0;

            if ipa_block_aligned && pa_block_aligned && remaining >= PMD_SIZE {
                unsafe { self.map_l2_block(ipa, pa, kind, alloc)?; }
                ipa = ipa.wrapping_add(PMD_SIZE);
                pa = pa.wrapping_add(PMD_SIZE);
            } else {
                unsafe { self.map_l3_page(ipa, pa, kind, alloc)?; }
                ipa = ipa.wrapping_add(PAGE_SIZE);
                pa = pa.wrapping_add(PAGE_SIZE);
            }
        }

        // Ensure all descriptor writes reach the table-walk hardware before
        // the caller enables Stage 2 (HCR_EL2.VM = 1).
        dsb_ishst();
        isb();
        Ok(())
    }
}

// ── Private mapping helpers ────────────────────────────────────────────────────

impl Stage2Tables {
    /// Install a 2MB block entry at L2 for the given IPA→PA pair.
    ///
    /// # Safety
    /// `ipa` and `pa` must be 2MB-aligned. `alloc` must be safe to use.
    unsafe fn map_l2_block(
        &self,
        ipa: u64,
        pa: u64,
        kind: MapKind,
        alloc: &mut BumpAllocator,
    ) -> Result<(), MapError> {
        let l2_pa = unsafe { self.ensure_l2_table(ipa, alloc)? };

        // L2 index: IPA[29:21] (9 bits).
        let l2_idx = ((ipa >> PMD_SHIFT) & 0x1FF) as usize;
        let entry_ptr = (l2_pa + (l2_idx as u64) * 8) as *mut u64;

        // bit[0] = 0 means the entry is invalid (safe to overwrite).
        let existing = unsafe { entry_ptr.read_volatile() };
        if existing & 1 != 0 {
            return Err(MapError::AlreadyMapped);
        }

        let desc = build_block_desc(pa & PA_MASK_2M, kind);
        unsafe { entry_ptr.write_volatile(desc) };
        Ok(())
    }

    /// Install a 4KB page entry at L3 for the given IPA→PA pair.
    ///
    /// # Safety
    /// `ipa` and `pa` must be 4KB-aligned. `alloc` must be safe to use.
    unsafe fn map_l3_page(
        &self,
        ipa: u64,
        pa: u64,
        kind: MapKind,
        alloc: &mut BumpAllocator,
    ) -> Result<(), MapError> {
        let l2_pa = unsafe { self.ensure_l2_table(ipa, alloc)? };
        let l3_pa = unsafe { ensure_l3_table(l2_pa, ipa, alloc)? };

        // L3 index: IPA[20:12] (9 bits).
        let l3_idx = ((ipa >> PAGE_SHIFT) & 0x1FF) as usize;
        let entry_ptr = (l3_pa + (l3_idx as u64) * 8) as *mut u64;

        let existing = unsafe { entry_ptr.read_volatile() };
        if existing & 1 != 0 {
            return Err(MapError::AlreadyMapped);
        }

        let desc = build_page_desc(pa & PA_MASK_4K, kind);
        unsafe { entry_ptr.write_volatile(desc) };
        Ok(())
    }

    /// Walk to the L2 table for the given IPA, allocating it if absent.
    ///
    /// The L1 index is bits [39:30] (10 bits) of `ipa`, indexing the
    /// concatenated 1024-entry root table.
    ///
    /// Returns the physical address of the L2 table.
    ///
    /// # Safety
    /// Same preconditions as `map_l2_block`.
    unsafe fn ensure_l2_table(
        &self,
        ipa: u64,
        alloc: &mut BumpAllocator,
    ) -> Result<u64, MapError> {
        // L1 index: IPA[39:30] — 10 bits, 0..1023 across the concatenated root.
        // PUD_SHIFT = 30 (from paging.rs).
        let l1_idx = ((ipa >> PUD_SHIFT) & 0x3FF) as usize;
        let l1_entry_ptr = (self.root_pa + (l1_idx as u64) * 8) as *mut u64;
        let l1_entry = unsafe { l1_entry_ptr.read_volatile() };

        // bits[1:0] == 0b11 → existing table descriptor.
        if l1_entry & 0b11 == 0b11 {
            return Ok(l1_entry & TABLE_MASK);
        }
        // bits[0] == 1 but not 0b11 → existing block at L1; can't mix.
        if l1_entry & 1 != 0 {
            return Err(MapError::AlreadyMapped);
        }
        // bits[0] == 0 → invalid; allocate a new L2 table.
        let l2_pa = unsafe { alloc.alloc_zeroed_page().ok_or(MapError::OutOfMemory)? };
        let table_desc = (l2_pa & TABLE_MASK) | stage2::DESC_TABLE;
        unsafe { l1_entry_ptr.write_volatile(table_desc) };
        Ok(l2_pa)
    }
}

/// Walk to the L3 table within `l2_pa` for the given IPA, allocating if absent.
///
/// # Safety
/// `l2_pa` must be the physical address of a valid L2 table page. `alloc` must
/// be safe to use.
unsafe fn ensure_l3_table(
    l2_pa: u64,
    ipa: u64,
    alloc: &mut BumpAllocator,
) -> Result<u64, MapError> {
    // L2 index: IPA[29:21] (9 bits). PMD_SHIFT = 21.
    let l2_idx = ((ipa >> PMD_SHIFT) & 0x1FF) as usize;
    let l2_entry_ptr = (l2_pa + (l2_idx as u64) * 8) as *mut u64;
    let l2_entry = unsafe { l2_entry_ptr.read_volatile() };

    if l2_entry & 0b11 == 0b11 {
        return Ok(l2_entry & TABLE_MASK);
    }
    if l2_entry & 1 != 0 {
        // Existing L2 block — can't install L3 table over a block.
        return Err(MapError::AlreadyMapped);
    }
    let l3_pa = unsafe { alloc.alloc_zeroed_page().ok_or(MapError::OutOfMemory)? };
    let table_desc = (l3_pa & TABLE_MASK) | stage2::DESC_TABLE;
    unsafe { l2_entry_ptr.write_volatile(table_desc) };
    Ok(l3_pa)
}

// ── Descriptor builders ───────────────────────────────────────────────────────

/// Assemble the lower attribute bits for a given `MapKind`.
/// Uses constants from `arm64::virt::stage2` — all verified against
/// linux-ref/arch/arm64/include/asm/{memory,kvm_pgtable}.h.
#[inline]
fn lower_attrs(kind: MapKind) -> u64 {
    match kind {
        MapKind::NormalRw => {
            // MemAttr = 0xF (Normal WB/WA) | SH = Inner Shareable | AF=1 | S2AP R+W
            stage2::MEMATTR_NORMAL | stage2::SH_INNER | stage2::AF | stage2::S2AP_RW
        }
        MapKind::NormalRo => {
            stage2::MEMATTR_NORMAL | stage2::SH_INNER | stage2::AF | stage2::S2AP_R
        }
        MapKind::DeviceRw => {
            // MemAttr = 0x1 (Device nGnRE) | SH = 0 (Non-Shareable) | AF=1 | S2AP R+W
            // Device memory is always Non-Shareable; SH bits left at 0.
            stage2::MEMATTR_DEVICE_nGnRE | stage2::AF | stage2::S2AP_RW
        }
    }
}

/// Assemble the upper attribute bits for a given `MapKind`.
#[inline]
fn upper_attrs(kind: MapKind) -> u64 {
    match kind {
        // Device MMIO must never be executed. XN_ALL sets bits [54:53].
        MapKind::DeviceRw => stage2::XN_ALL,
        _ => 0,
    }
}

/// Build a Stage 2 L2 block descriptor (maps 2MB).
/// `pa` must already have bits [20:0] cleared by the caller via PA_MASK_2M.
#[inline]
fn build_block_desc(pa: u64, kind: MapKind) -> u64 {
    stage2::DESC_BLOCK | lower_attrs(kind) | pa | upper_attrs(kind)
}

/// Build a Stage 2 L3 page descriptor (maps 4KB).
/// `pa` must already have bits [11:0] cleared by the caller via PA_MASK_4K.
#[inline]
fn build_page_desc(pa: u64, kind: MapKind) -> u64 {
    stage2::DESC_PAGE | lower_attrs(kind) | pa | upper_attrs(kind)
}

// ─────────────────────────────────────────────────────────────────────────────
// TLB maintenance
//
// Any modification to Stage 2 page table entries requires a TLB invalidation
// to prevent the guest from using stale cached translations.
//
// Mandatory sequence (ARM ARM DDI0487 Section D5.10.2):
//   1. DSB ISH      — wait for all prior table writes to be visible in the
//                     inner-shareable domain before the TLBI hardware reads them
//   2. TLBI VMALLS12E1IS — invalidate all EL1&0 Stage 1 + Stage 2 TLB entries
//                     for the current VMID in the inner-shareable domain
//   3. DSB ISH      — wait for the TLBI broadcast to complete on all PEs
//   4. ISB          — flush the instruction pipeline so the next instruction
//                     fetch uses the clean TLB state
//
// TLBI operand VMALLS12E1IS is the correct choice when:
//   - HCR_EL2.VM = 1 (Stage 2 is active)
//   - We want to flush both Stage 1 and Stage 2 entries (VMALLS12)
//   - We want the invalidation to broadcast to all cores (IS suffix)
//
// This is NOT the same as TLBI ALLE2, which only clears EL2-regime entries.
// ─────────────────────────────────────────────────────────────────────────────

/// Invalidate all Stage 1 and Stage 2 TLB entries for the current VMID across
/// the entire inner-shareable domain.
///
/// Call this once after all Stage 2 mappings for a guest are installed, and
/// after any subsequent permission change or removal.
///
/// Reference: ARM ARM DDI0487 Section D5.10.2
#[inline]
pub fn tlb_flush_s1s2_vmid() {
    dsb_ish();
    unsafe {
        // TLBI VMALLS12E1IS: Stage-1-and-2, all VMIDs, EL1&0 regime, Inner Shareable.
        // Source: ARM ARM DDI0487 Section C5.5.14
        asm!("tlbi vmalls12e1is", options(nomem, nostack, preserves_flags));
    }
    dsb_ish();
    isb();
}

// ─────────────────────────────────────────────────────────────────────────────
// ARM SMMU v3 Stream Table Entry
//
// Every DMA-capable device on the SMMU is identified by a StreamID (derived
// from PCIe RID or AMBA bus number). The SMMU indexes the Stream Table with
// the StreamID to find the STE that controls translation for that device.
//
// STE format: ARM SMMU v3 spec IHI0070E Section 6.3 (Table 6-9).
//   64 bytes = 8 × u64 words.
//   Word 0: Valid bit + Config field + (S1 CD base, if S1 enabled)
//   Word 2: Stage 2 translation parameters (mirror of VTCR_EL2)
//   Word 3: Stage 2 translation table base address (S2TTB)
//   Words 1, 4-7: other fields (all zero for AETHER's S2-only config)
//
// AETHER uses Config = S2_ONLY (6), which applies Stage 2 translation to all
// DMA from the assigned device. This restricts device DMA to the same PA range
// as Android's CPU — the fundamental DMA isolation guarantee.
//
// STE word 0 Valid/Config ordering:
//   The SMMU reads the STE non-atomically. To prevent a partial STE being
//   interpreted as valid, write words 1..7 first (with DSB), then write word 0
//   last to commit the Valid bit.
//
// Field sources:
//   IHI0070E Table 6-9 (STE field positions)
//   linux-ref/drivers/iommu/arm/arm-smmu-v3/arm-smmu-v3.h (STRTAB_STE_*)
// ─────────────────────────────────────────────────────────────────────────────

/// ARM SMMU v3 Stream Table Entry: 64 bytes, 64-byte aligned.
///
/// Field positions verified from IHI0070E Table 6-9 and
/// `linux-ref/drivers/iommu/arm/arm-smmu-v3/arm-smmu-v3.h` STRTAB_STE_* defines.
#[derive(Clone, Copy)]
#[repr(C, align(64))]
pub struct SmmuSte {
    words: [u64; 8],
}

/// STE Word 0 field constants.
///
/// Source: IHI0070E Table 6-9, linux STRTAB_STE_0_* defines.
pub mod ste_w0 {
    /// Bit 0: V — Valid. 1 = this STE is active. Write last when committing.
    /// Source: IHI0070E Table 6-9 `STE.V`, linux `STRTAB_STE_0_V BIT(0)`
    pub const VALID: u64 = 1 << 0;

    /// Bits [4:1]: Config[3:0] — controls translation mode for this stream.
    /// Source: IHI0070E Table 6-9 `STE.Config`, linux `STRTAB_STE_0_CFG GENMASK(4,1)`
    pub const CFG_SHIFT: u32 = 1;

    /// Config = 0b0000 (0): Abort all transactions. Hardware default for all-zero STE.
    pub const CFG_ABORT:   u64 = 0b0000 << CFG_SHIFT;
    /// Config = 0b0100 (4): Bypass — no translation. Use as safe placeholder.
    /// Source: linux `STRTAB_STE_0_CFG_BYPASS 4UL`
    pub const CFG_BYPASS:  u64 = 0b0100 << CFG_SHIFT;
    /// Config = 0b0101 (5): Stage 1 translation only.
    pub const CFG_S1_ONLY: u64 = 0b0101 << CFG_SHIFT;
    /// Config = 0b0110 (6): Stage 2 translation only. AETHER's choice.
    /// Restricts device DMA to the Android Stage 2 page tables.
    /// Source: linux `STRTAB_STE_0_CFG_S2_TRANS 6UL`
    pub const CFG_S2_ONLY: u64 = 0b0110 << CFG_SHIFT;
    /// Config = 0b0111 (7): Stage 1 + Stage 2 translation.
    pub const CFG_S1S2:    u64 = 0b0111 << CFG_SHIFT;
}

/// STE Word 2 field constants — Stage 2 translation parameters.
///
/// These fields mirror VTCR_EL2 semantics and must match the VTCR_EL2
/// configured by `arm64::virt::configure_el2_virt()`.
///
/// Source: IHI0070E Table 6-9, linux STRTAB_STE_2_* defines.
pub mod ste_w2 {
    /// Bits [15:0]: S2VMID — identifies which VMID's Stage 2 tables to use.
    pub const S2VMID_MASK: u64 = 0xFFFF;
    /// Bits [21:16]: S2T0SZ — matches VTCR_EL2.T0SZ (24 for 40-bit IPA).
    pub const S2T0SZ_SHIFT: u32 = 16;
    /// Bits [23:22]: S2SL0 — starting level, matches VTCR_EL2.SL0 (1 = Level 1).
    pub const S2SL0_SHIFT: u32 = 22;
    /// Bits [25:24]: S2IR0 — inner cacheability of Stage 2 table walks.
    pub const S2IR0_SHIFT: u32 = 24;
    /// Bits [27:26]: S2OR0 — outer cacheability of Stage 2 table walks.
    pub const S2OR0_SHIFT: u32 = 26;
    /// Bits [29:28]: S2SH0 — shareability of Stage 2 table walks.
    pub const S2SH0_SHIFT: u32 = 28;
    /// Bits [31:30]: S2TG — translation granule (0b00 = 4KB).
    pub const S2TG_SHIFT: u32 = 30;
    /// Bits [34:32]: S2PS — physical address size (0b101 = 48-bit).
    pub const S2PS_SHIFT: u32 = 32;
    /// Bit 35: S2AA64 — 1 = use AArch64 Stage 2 descriptor format. Always 1.
    pub const S2AA64: u64 = 1 << 35;
    /// Bit 45: S2PTW — Protected Table Walk (mirrors HCR_EL2.PTW).
    /// Faults if Stage 1 table walk accesses device memory; prevents side channels.
    pub const S2PTW: u64 = 1 << 45;

    // Cacheability value for WB/WA (matches VTCR_EL2 IRGN0/ORGN0 = 0b01).
    pub const CACHE_WBWA: u64 = 0b01;
    // Shareability value for Inner Shareable (matches VTCR_EL2 SH0 = 0b11).
    pub const SH_INNER: u64 = 0b11;
}

/// STE Word 3 field constants — Stage 2 table base address.
///
/// Source: IHI0070E Table 6-9, linux `STRTAB_STE_3_S2TTB_MASK GENMASK_ULL(51,4)`.
pub mod ste_w3 {
    /// Bits [51:4]: S2TTB — Stage 2 root table PA, right-shifted by 4.
    /// Since AETHER's root is 8KiB-aligned, bits [3:0] of the PA are always 0
    /// and the PA can be stored directly (the 4-bit right-shift has no effect).
    pub const S2TTB_MASK: u64 = 0x000F_FFFF_FFFF_FFF0;
}

impl SmmuSte {
    /// An all-zero STE — the SMMU treats this as Abort.
    /// The stream table is initialised to this; devices without an explicit
    /// STE will have all their DMA transactions aborted, which is the safe
    /// default.
    #[inline]
    pub const fn invalid() -> Self {
        Self { words: [0u64; 8] }
    }

    /// A Bypass STE — DMA from this StreamID passes through untranslated.
    ///
    /// Use this as a temporary placeholder while building Stage 2 tables.
    /// Replace with `stage2_only()` before enabling the SMMU in production.
    #[inline]
    pub fn bypass() -> Self {
        let mut ste = Self::invalid();
        ste.words[0] = ste_w0::VALID | ste_w0::CFG_BYPASS;
        ste
    }

    /// A Stage 2-only STE for a device assigned to the Android partition.
    ///
    /// DMA from this StreamID is translated through AETHER's Stage 2 tables,
    /// restricting the device to the same IPA→PA mappings as Android's CPU.
    ///
    /// # Arguments
    /// - `vmid`: VMID of the Android partition (typically `vttbr_el2::VMID_ANDROID = 1`).
    /// - `s2ttb_pa`: Physical address of the Stage 2 root table — the same
    ///   value passed to `configure_el2_virt()` (i.e., `Stage2Tables::root_pa()`).
    ///
    /// The Stage 2 parameters embedded here must match `VTCR_EL2::CONFIG`:
    ///   T0SZ=24, SL0=1 (L1 start), 4KB granule, 48-bit PA, WBWA, Inner Shareable.
    pub fn stage2_only(vmid: u16, s2ttb_pa: u64) -> Self {
        let mut ste = Self::invalid();

        // Word 0: Valid + Config = S2_ONLY (write last when committing via write_ste).
        ste.words[0] = ste_w0::VALID | ste_w0::CFG_S2_ONLY;

        // Word 2: Stage 2 translation parameters.
        // All field values mirror VTCR_EL2::CONFIG (verified in arm64/virt.rs).
        let t0sz: u64 = VTCR_T0SZ_40BIT;   // 24 — 40-bit IPA space
        let sl0:  u64 = 0b01;               // Start at Level 1 (matches SL0_LEVEL1)
        let ir0:  u64 = ste_w2::CACHE_WBWA; // Inner WB/WA (matches IRGN0_WBWA)
        let or0:  u64 = ste_w2::CACHE_WBWA; // Outer WB/WA (matches ORGN0_WBWA)
        let sh0:  u64 = ste_w2::SH_INNER;   // Inner Shareable (matches SH0_INNER)
        let tg:   u64 = 0b00;               // 4KB granule (matches TG0_4K)
        let ps:   u64 = 0b101;              // 48-bit PA (matches PS_48BIT >> PS_SHIFT)
        ste.words[2] = (vmid as u64)                   // S2VMID[15:0]
            | (t0sz << ste_w2::S2T0SZ_SHIFT)
            | (sl0  << ste_w2::S2SL0_SHIFT)
            | (ir0  << ste_w2::S2IR0_SHIFT)
            | (or0  << ste_w2::S2OR0_SHIFT)
            | (sh0  << ste_w2::S2SH0_SHIFT)
            | (tg   << ste_w2::S2TG_SHIFT)
            | (ps   << ste_w2::S2PS_SHIFT)
            | ste_w2::S2AA64
            | ste_w2::S2PTW;

        // Word 3: S2TTB — Stage 2 root table physical address.
        // Mask to bits [51:4]; our 8KiB-aligned PA has bits [3:0] = 0 already.
        ste.words[3] = s2ttb_pa & ste_w3::S2TTB_MASK;

        ste
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SMMU stream table
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum number of StreamIDs in AETHER's linear stream table.
///
/// A linear table of 256 entries is sufficient for all devices on a typical
/// Snapdragon SoC. Real SMMU hardware can support up to 2^StreamID_Width entries;
/// this is configured via STRTAB_BASE_CFG.LOG2SIZE (set to 8 for 256 entries).
pub const SMMU_MAX_STREAMS: usize = 256;

/// AETHER's SMMU linear stream table — an array of `SMMU_MAX_STREAMS` STEs.
///
/// Must be placed in DRAM accessible to the SMMU's internal DMA engine. Use a
/// `static mut` for this (see `main.rs`) so its physical address is stable.
///
/// Initialisation procedure (caller's responsibility after constructing this):
///   1. Write all STEs (this table initialises to all-Abort = all-zero).
///   2. For each DMA device assigned to Android: call `write_ste(id, SmmuSte::stage2_only(...))`.
///   3. Write STRTAB_BASE = base_pa() to the SMMU MMIO register.
///   4. Write STRTAB_BASE_CFG: FMT=linear (0), LOG2SIZE=8, RA=1.
///   5. Write CR0.SMMUEN = 1 and poll CR0ACK until acknowledged.
///
/// Reference: IHI0070E Chapter 6 (register interface), Section 3.4 (stream tables)
///            linux-ref/drivers/iommu/arm/arm-smmu-v3/arm-smmu-v3.c
///            arm_smmu_init_strtab_linear(), arm_smmu_write_cr0()
#[repr(C, align(64))]
pub struct SmmuStreamTable {
    entries: [SmmuSte; SMMU_MAX_STREAMS],
}

impl SmmuStreamTable {
    /// Create a stream table with all entries set to Abort (all-zero STE).
    pub const fn new_aborted() -> Self {
        Self {
            entries: [SmmuSte { words: [0u64; 8] }; SMMU_MAX_STREAMS],
        }
    }

    /// Write one stream table entry for `stream_id`.
    ///
    /// Words 1–7 are written before Word 0 (the Valid/Config word), ensuring
    /// the SMMU never observes a partial STE as valid. Each write group is
    /// separated by DSB ISH to enforce ordering with the SMMU's DMA engine.
    ///
    /// # Safety
    /// - `stream_id` must be < `SMMU_MAX_STREAMS`.
    /// - Must be called before the SMMU is enabled, or with explicit
    ///   synchronization to ensure the SMMU does not observe a partial write.
    pub unsafe fn write_ste(&mut self, stream_id: usize, ste: SmmuSte) {
        // Bounds check is always active (not just debug) because a bad stream_id
        // would corrupt adjacent memory visible to the SMMU.
        assert!(stream_id < SMMU_MAX_STREAMS, "stream_id out of range");

        let base = unsafe {
            self.entries.as_mut_ptr().add(stream_id) as *mut u64
        };

        // Write words 1..7 first (non-Valid content).
        // The SMMU samples Valid last; writing it first would expose a partial STE.
        for i in 1_usize..8 {
            unsafe { base.add(i).write_volatile(ste.words[i]) };
        }
        // DSB ISH: ensure words 1..7 are visible to the SMMU before word 0.
        dsb_ish();
        // Commit: write Valid/Config (word 0) last.
        unsafe { base.write_volatile(ste.words[0]) };
        // DSB ISH: ensure the full STE is visible before the caller returns.
        dsb_ish();
    }

    /// Physical address of the stream table base.
    ///
    /// Write this value to the SMMU's STRTAB_BASE register (offset 0x80).
    ///
    /// # Safety
    /// Valid only while `self` is live and not moved. Use a `static` instance
    /// to guarantee stability.
    pub unsafe fn base_pa(&self) -> u64 {
        self as *const Self as u64
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Compile-time assertions
//
// These catch bit-position regressions and layout errors that would silently
// produce wrong descriptors or corrupt SMMU stream table entries.
// ─────────────────────────────────────────────────────────────────────────────

const _: () = {
    use core::mem::{align_of, size_of};

    // ── SmmuSte layout ────────────────────────────────────────────────────────
    assert!(size_of::<SmmuSte>() == 64, "SmmuSte must be exactly 64 bytes (8 × u64)");
    assert!(align_of::<SmmuSte>() == 64, "SmmuSte must be 64-byte aligned");

    // ── SmmuStreamTable alignment ─────────────────────────────────────────────
    assert!(align_of::<SmmuStreamTable>() >= 64, "SmmuStreamTable must be at least 64-byte aligned");

    // ── Output address masks must not touch descriptor type bits [1:0] ────────
    assert!(PA_MASK_2M & 0b11 == 0, "PA_MASK_2M overlaps descriptor type bits");
    assert!(PA_MASK_4K & 0b11 == 0, "PA_MASK_4K overlaps descriptor type bits");
    assert!(TABLE_MASK & 0b11 == 0, "TABLE_MASK overlaps descriptor type bits");

    // ── 2MB block mask must zero IPA bits [20:0] ──────────────────────────────
    assert!(PA_MASK_2M & ((1u64 << 21) - 1) == 0, "PA_MASK_2M must zero bits [20:0]");

    // ── Stage 2 descriptor type encodings (ARM ARM DDI0487 Table D5-1) ────────
    assert!(stage2::DESC_BLOCK == 0b01, "DESC_BLOCK must be 0b01");
    assert!(stage2::DESC_TABLE == 0b11, "DESC_TABLE must be 0b11");
    assert!(stage2::DESC_PAGE  == 0b11, "DESC_PAGE  must be 0b11");

    // ── MemAttr encoding (ARM ARM Table D5-22, via linux-ref memory.h) ────────
    // MEMATTR_NORMAL = MT_S2_NORMAL (0xF) << MEMATTR_SHIFT (2) = 0x3C
    assert!(stage2::MEMATTR_NORMAL == 0x3C,
        "MEMATTR_NORMAL must be 0x3C (MT_S2_NORMAL=0xF shifted to bits [5:2])");
    // MEMATTR_DEVICE_nGnRE = MT_S2_DEVICE_nGnRE (0x1) << 2 = 0x04
    assert!(stage2::MEMATTR_DEVICE_nGnRE == 0x04,
        "MEMATTR_DEVICE_nGnRE must be 0x04 (MT_S2_DEVICE_nGnRE=0x1 shifted to bits [5:2])");

    // ── AF (Access Flag) must be bit 10 ───────────────────────────────────────
    assert!(stage2::AF == 1 << 10, "AF must be bit 10 (ARM ARM DDI0487 Table D5-3)");

    // ── STE Config field positions ─────────────────────────────────────────────
    // CFG_BYPASS  = 4 << 1 = 0x08; CFG_S2_ONLY = 6 << 1 = 0x0C
    assert!(ste_w0::CFG_BYPASS  == 0x08, "CFG_BYPASS must be 0x08 (Config=4 at bits [4:1])");
    assert!(ste_w0::CFG_S2_ONLY == 0x0C, "CFG_S2_ONLY must be 0x0C (Config=6 at bits [4:1])");

    // ── VTCR_T0SZ_40BIT sanity ────────────────────────────────────────────────
    assert!(VTCR_T0SZ_40BIT == 24, "VTCR_T0SZ_40BIT must be 24 for 40-bit IPA");
};
