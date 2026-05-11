// ch06: The Virtualization Extensions
//
// The ARM Virtualization Extensions (ARM ARM DDI0487, Part G) are what make
// AETHER possible. This module owns every EL2 configuration register that
// controls the boundary between the hypervisor and its Android guest.
//
// Scope of this module:
//   - HCR_EL2 guest-mode bit field extensions (beyond the basic set in regs.rs)
//   - VTCR_EL2: Stage 2 translation parameters (granule, IPA size, levels)
//   - VTTBR_EL2: Stage 2 table base address + VMID tag
//   - Stage 2 page table descriptor attribute encoding
//   - CPTR_EL2: FP/SIMD trap control for EL1/EL0
//   - GIC Virtualization Extension: ICH_HCR_EL2, ICH_LR (List Registers)
//
// Design choice: nVHE (HCR_EL2.E2H = 0)
//   AETHER uses the traditional nVHE model rather than VHE (E2H=1). Under nVHE,
//   the hypervisor runs in EL2 with its own register bank, fully isolated from
//   the EL1 guest context. VHE blurs this boundary for hosting-OS convenience;
//   AETHER has no hosting OS and gains nothing from VHE's complexity while losing
//   isolation guarantees. Reference: ARM ARM DDI0487 Section G4.
//
// Primary sources (all values verified against):
//   - linux-ref/arch/arm64/tools/sysreg  (authoritative bit positions)
//   - linux-ref/arch/arm64/include/asm/kvm_arm.h
//   - linux-ref/arch/arm64/include/asm/kvm_pgtable.h
//   - linux-ref/arch/arm64/include/asm/memory.h
//   - linux-ref/arch/arm64/include/asm/sysreg.h
//
// Skill guide warning (ch06): This chapter has the lowest confidence level.
//   Every constant below is cited to a specific file and line number.
//   Stage 2 descriptors use a DIFFERENT attribute encoding than Stage 1.

use core::arch::asm;

use super::barriers::{dsb_ish, isb};

// ─────────────────────────────────────────────────────────────────────────────
// HCR_EL2 — Hypervisor Configuration Register (guest-mode additions)
//
// regs.rs already defines the bits AETHER itself uses (RW, E2H, TVM, etc.).
// This submodule adds the full set of guest-mode trap/routing bits needed
// when actually running an EL1 guest.
//
// All bit positions verified from:
//   linux-ref/arch/arm64/tools/sysreg lines 3885–3950  (Sysreg HCR_EL2)
// ─────────────────────────────────────────────────────────────────────────────

/// HCR_EL2 bit definitions for guest configuration.
///
/// All positions verified from `linux-ref/arch/arm64/tools/sysreg`
/// at the `Sysreg HCR_EL2` block (lines 3885–3950).
pub mod hcr_el2 {
    // ── Low-bits: routing and Stage 2 control ──────────────────────────────

    /// Bit 0: VM — Enable Stage 2 address translation.
    /// Must be 1 when running a guest. Writing 0 disables the Stage 2 MMU.
    /// Source: sysreg line 3949 `Field 0 VM`
    pub const VM: u64 = 1 << 0;

    /// Bit 1: SWIO — Set/way invalidate → set/way clean+invalidate broadcast.
    /// Ensures guest cache maintenance operations have correct coherency effect.
    /// Source: sysreg line 3948 `Field 1 SWIO`
    pub const SWIO: u64 = 1 << 1;

    /// Bit 2: PTW — Protected Table Walk.
    /// Take a Stage 2 fault if a Stage 1 table walk accesses device memory.
    /// Prevents information leakage through table-walk side channels.
    /// Source: sysreg line 3947 `Field 2 PTW`
    pub const PTW: u64 = 1 << 2;

    /// Bit 3: FMO — FIQ Mask Override. Routes FIQ to EL2.
    /// Source: sysreg line 3946 `Field 3 FMO`
    pub const FMO: u64 = 1 << 3;

    /// Bit 4: IMO — IRQ Mask Override. Routes IRQ to EL2.
    /// Source: sysreg line 3945 `Field 4 IMO`
    pub const IMO: u64 = 1 << 4;

    /// Bit 5: AMO — Asynchronous abort Mask Override. Routes SError to EL2.
    /// Source: sysreg line 3944 `Field 5 AMO`
    pub const AMO: u64 = 1 << 5;

    /// Bit 9: FB — Force Broadcast.
    /// Forces EL1 cache and TLB maintenance operations to broadcast to all
    /// inner-shareable domain processors, as required for coherent multi-core.
    /// Source: sysreg line 3940 `Field 9 FB`
    pub const FB: u64 = 1 << 9;

    /// Bits 11:10 — BSU: Barrier Shareability Upgrade.
    /// Upgrades EL1-issued barriers to inner-shareable domain.
    /// BSU_IS (0b01 in bits 11:10) = bit 10 only.
    /// Source: sysreg lines 3934–3939 `UnsignedEnum 11:10 BSU` / `0b01 IS`
    pub const BSU_IS: u64 = 1 << 10;

    /// Bit 13: TWI — Trap WFI.
    /// Guest WFI instruction traps to EL2, letting AETHER implement idle.
    /// Source: sysreg line 3932 `Field 13 TWI`
    pub const TWI: u64 = 1 << 13;

    /// Bit 14: TWE — Trap WFE.
    /// Guest WFE instruction traps to EL2.
    /// Source: sysreg line 3931 `Field 14 TWE`
    pub const TWE: u64 = 1 << 14;

    /// Bit 16: TID1 — Trap ID register group 1.
    /// Traps guest reads of REVIDR_EL1, AIDR_EL1, SMIDR_EL1 to EL2.
    /// Source: sysreg line 3929 `Field 16 TID1`
    pub const TID1: u64 = 1 << 16;

    /// Bit 18: TID3 — Trap ID register group 3.
    /// Traps guest reads of group-3 ID registers (CPU feature discovery).
    /// Allows AETHER to control what capabilities the guest believes it has.
    /// Source: sysreg line 3927 `Field 18 TID3`
    pub const TID3: u64 = 1 << 18;

    /// Bit 19: TSC — Trap SMC.
    /// Guest SMC instructions trap to EL2. AETHER filters and forwards safe
    /// SMC calls to EL3 firmware; all others are rejected.
    /// Source: sysreg line 3926 `Field 19 TSC`
    pub const TSC: u64 = 1 << 19;

    /// Bit 20: TIDCP — Trap L2CTLR/L2ECTLR.
    /// Traps implementation-defined cache control register accesses.
    /// Source: sysreg line 3925 `Field 20 TIDCP`
    pub const TIDCP: u64 = 1 << 20;

    /// Bit 21: TACR — Trap ACTLR.
    /// Traps guest accesses to ACTLR_EL1 (Auxiliary Control Register).
    /// Source: sysreg line 3924 `Field 21 TACR`
    pub const TACR: u64 = 1 << 21;

    /// Bit 22: TSW — Trap set/way cache operations.
    /// Traps EL1 DC ISW/CSW/CISW instructions to EL2.
    /// Source: sysreg line 3923 `Field 22 TSW`
    pub const TSW: u64 = 1 << 22;

    /// Bit 31: RW — Lower EL AArch64.
    /// Must be 1: AETHER only supports 64-bit Android (HCR_EL2.E2H=0 + RW=1).
    /// Source: sysreg line 3914 `Field 31 RW`
    pub const RW: u64 = 1 << 31;

    /// Bit 35: TLOR — Trap LO Region registers.
    /// Source: sysreg line 3910 `Field 35 TLOR`
    pub const TLOR: u64 = 1 << 35;

    // ── Composite: full guest-mode HCR_EL2 value ──────────────────────────
    //
    // Derived from linux-ref/arch/arm64/include/asm/kvm_arm.h HCR_GUEST_FLAGS
    // (lines 100–103), translated to our verified bit positions above.
    // Reference: kvm_arm.h line 100:
    //   HCR_GUEST_FLAGS = HCR_TSC | HCR_TSW | HCR_TWE | HCR_TWI | HCR_VM |
    //       HCR_BSU_IS | HCR_FB | HCR_TACR | HCR_AMO | HCR_SWIO | HCR_TIDCP |
    //       HCR_RW | HCR_TLOR | HCR_FMO | HCR_IMO | HCR_PTW | HCR_TID3 | HCR_TID1

    /// Combined HCR_EL2 value for running the Android guest at EL1.
    /// Setting this (with VM=1) enables Stage 2 translation and routes all
    /// exception types to EL2.
    pub const GUEST_FLAGS: u64 = VM | SWIO | PTW | FMO | IMO | AMO | FB |
        BSU_IS | TWI | TWE | TID1 | TID3 | TSC | TIDCP | TACR | TSW | RW | TLOR;
}

// ─────────────────────────────────────────────────────────────────────────────
// VTCR_EL2 — Virtualization Translation Control Register
//
// Controls Stage 2 translation parameters: IPA address space size, translation
// granule, starting level, shareability, and cacheability of table walks.
//
// AETHER configuration (40-bit IPA, 4KB granule, 3 levels, 48-bit PA):
//   T0SZ = 64 − 40 = 24          → bits [5:0]  (paging.rs VTCR_T0SZ_40BIT)
//   SL0  = 1 (Level 1 start)     → bits [7:6]  (3 levels with 4KB granule)
//   IRGN0 = 0b01 (WB/WA)         → bits [9:8]
//   ORGN0 = 0b01 (WB/WA)         → bits [11:10]
//   SH0  = 0b11 (Inner Share.)   → bits [13:12]
//   TG0  = 0b00 (4KB)            → bits [15:14]
//   PS   = 0b101 (48-bit PA)     → bits [18:16]
//   VS   = 0b0  (8-bit VMID)     → bit  [19]
//   Bit 31 = RES1                → always 1
//
// SL0=1 derivation (4KB granule):
//   SL0_BASE(4K) = 2  (kvm_arm.h line 177: VTCR_EL2_TGRAN_SL0_BASE = 2UL)
//   Entry_level for 40-bit IPA: ceil((40−12)/9) = ceil(3.1) → 3 levels
//   Entry_level index = 1  (starting at Level 1)
//   SL0 = SL0_BASE − Entry_level = 2 − 1 = 1
//
// All field positions verified from:
//   linux-ref/arch/arm64/tools/sysreg lines 4535–4590  (Sysreg VTCR_EL2)
// ─────────────────────────────────────────────────────────────────────────────

/// VTCR_EL2 bit and field definitions.
///
/// Positions verified from `linux-ref/arch/arm64/tools/sysreg`
/// at the `Sysreg VTCR_EL2` block (lines 4535–4590).
pub mod vtcr_el2 {
    use crate::arm64::paging::VTCR_T0SZ_40BIT;

    // ── Field constants ────────────────────────────────────────────────────

    /// Bit 31: RES1 — must always be written 1.
    /// Source: sysreg line 4550 `Res1 31`
    pub const RES1: u64 = 1 << 31;

    // VS (bit 19): 0 = 8-bit VMID — sufficient for AETHER (1 Android guest).
    // Source: sysreg lines 4561–4564 `Enum 19 VS / 0b0 8BIT`
    // Value 0 — implicit in combined constant below.

    /// PS field shift position (bits [18:16]).
    /// Source: sysreg line 4565 `Field 18:16 PS`
    pub const PS_SHIFT: u32 = 16;

    /// PS = 0b101: 48-bit physical address output size.
    /// Matches PA_BITS = 48 in paging.rs.
    /// ARM ARM DDI0487 VTCR_EL2.PS encoding: 0b101 = 48-bit.
    pub const PS_48BIT: u64 = 0b101 << PS_SHIFT;

    /// TG0 field (bits [15:14]): 0b00 = 4KB granule.
    /// Source: sysreg lines 4566–4570 `Enum 15:14 TG0 / 0b00 4K`
    pub const TG0_4K: u64 = 0b00 << 14;

    /// SH0 field (bits [13:12]): 0b11 = Inner Shareable.
    /// Inner Shareable ensures Stage 2 table walk coherency across all
    /// cores sharing the inner cache domain.
    /// Source: sysreg lines 4571–4575 `Enum 13:12 SH0 / 0b11 INNER`
    pub const SH0_INNER: u64 = 0b11 << 12;

    /// ORGN0 field (bits [11:10]): 0b01 = Write-Back Write-Allocate Cacheable.
    /// Outer cacheability for Stage 2 table walks.
    /// Source: sysreg lines 4576–4581 `Enum 11:10 ORGN0 / 0b01 WBWA`
    pub const ORGN0_WBWA: u64 = 0b01 << 10;

    /// IRGN0 field (bits [9:8]): 0b01 = Write-Back Write-Allocate Cacheable.
    /// Inner cacheability for Stage 2 table walks.
    /// Source: sysreg lines 4582–4587 `Enum 9:8 IRGN0 / 0b01 WBWA`
    pub const IRGN0_WBWA: u64 = 0b01 << 8;

    /// SL0 field (bits [7:6]): 0b01 = Start at Level 1.
    /// With 4KB granule and 40-bit IPA, Stage 2 translation uses 3 levels
    /// starting at Level 1.
    /// Source: sysreg line 4588 `Field 7:6 SL0`
    /// Derivation: kvm_arm.h line 177 `VTCR_EL2_TGRAN_SL0_BASE = 2UL`
    ///             SL0 = SL0_BASE(4K) − (4 − levels) = 2 − (4 − 3) = 1
    pub const SL0_LEVEL1: u64 = 0b01 << 6;

    // T0SZ field (bits [5:0]): imported from paging.rs as VTCR_T0SZ_40BIT = 24.
    // Source: sysreg line 4589 `Field 5:0 T0SZ`

    // ── Combined configuration value ───────────────────────────────────────

    /// VTCR_EL2 value for AETHER's 40-bit IPA, 4KB granule, 48-bit PA configuration.
    ///
    /// Breakdown:
    ///   - T0SZ = 24   (40-bit IPA, bits [5:0])
    ///   - SL0  = 1    (Level 1 start, bits [7:6])
    ///   - IRGN0 = 1   (WB/WA, bits [9:8])
    ///   - ORGN0 = 1   (WB/WA, bits [11:10])
    ///   - SH0  = 3    (Inner Shareable, bits [13:12])
    ///   - TG0  = 0    (4KB granule, bits [15:14])
    ///   - PS   = 5    (48-bit PA, bits [18:16])
    ///   - VS   = 0    (8-bit VMID, bit [19])
    ///   - Bit 31 = 1  (RES1)
    ///
    /// Numerically: 0x8005_3558
    pub const CONFIG: u64 = RES1 | PS_48BIT | TG0_4K | SH0_INNER |
        ORGN0_WBWA | IRGN0_WBWA | SL0_LEVEL1 | (VTCR_T0SZ_40BIT as u64);
}

// ─────────────────────────────────────────────────────────────────────────────
// VTTBR_EL2 — Virtualization Translation Table Base Register
//
// Holds the physical address of the Stage 2 translation table root AND the
// VMID that tags TLB entries for this guest.
//
// Layout (8-bit VMID, VS=0):
//   bits [63:56]: reserved (must be 0 for 8-bit VMID)
//   bits [55:48]: VMID  — tags TLB entries so guest translations don't
//                         conflict with each other or with EL2 translations
//   bits [47:x]:  BADDR — physical address of Stage 2 L1 table root, where
//                         x = IPA_BITS − (PAGE_SHIFT − 3) × levels = 40 − 9×3 = 13
//   bits [x−1:1]: must be 0 (alignment requirement)
//   bit  [0]:     CnP   — Common not Private (set when sharing VMID page tables
//                         across multiple PEs; AETHER leaves this 0)
//
// Source: linux-ref/arch/arm64/include/asm/kvm_arm.h lines 261–263
//   #define VTTBR_CNP_BIT     (UL(1))
//   #define VTTBR_VMID_SHIFT  (UL(48))
//   #define VTTBR_VMID_MASK(size) (_AT(u64, (1 << size) - 1) << VTTBR_VMID_SHIFT)
// ─────────────────────────────────────────────────────────────────────────────

/// VTTBR_EL2 constants and builder.
///
/// Values verified from `linux-ref/arch/arm64/include/asm/kvm_arm.h`
/// lines 261–263 (VTTBR_VMID_SHIFT, VTTBR_VMID_MASK, VTTBR_CNP_BIT).
pub mod vttbr_el2 {
    /// VMID field shift position (bits [55:48] for 8-bit VMID).
    /// Source: kvm_arm.h line 262 `#define VTTBR_VMID_SHIFT  (UL(48))`
    pub const VMID_SHIFT: u32 = 48;

    /// Mask for the 8-bit VMID field at its shifted position.
    pub const VMID_MASK: u64 = 0xFF << VMID_SHIFT;

    /// VMID assigned to AETHER's Android partition.
    /// VMID 0 is typically used by the host (or left zeroed in EL2-only mode).
    /// Android receives VMID 1 — first non-host VMID.
    pub const VMID_ANDROID: u8 = 1;

    /// Build a VTTBR_EL2 value from a VMID and the physical address of the
    /// Stage 2 Level 1 table root.
    ///
    /// The table must be aligned to 2^x bytes, where
    /// x = IPA_BITS − (PAGE_SHIFT − 3) × levels = 40 − 9×3 = 13 (8KiB alignment).
    ///
    /// # Arguments
    /// - `vmid`: 8-bit Virtual Machine ID (0–255 when VTCR_EL2.VS=0)
    /// - `table_pa`: physical address of Stage 2 L1 table root (must be 8KiB aligned)
    #[inline]
    pub const fn build(vmid: u8, table_pa: u64) -> u64 {
        ((vmid as u64) << VMID_SHIFT) | table_pa
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Stage 2 page table descriptor attributes
//
// WARNING: Stage 2 descriptors use DIFFERENT attribute encoding than Stage 1.
// The skill guide identifies this as the most common AI mistake in this domain.
//
// Key differences from Stage 1:
//   - S2AP  (bits [7:6]): 2-bit field controlling read/write access for
//                          EL1 and EL0 together (not the Stage 1 AP field)
//   - MemAttr (bits [5:2]): 4-bit field selecting memory type from an internal
//                            Stage 2 table (NOT an index into MAIR_EL1)
//   - XN    (bits [54:53]): 2-bit extended execute-never field (not 1-bit)
//   - AF    (bit  [10]):    Access Flag — identical semantics to Stage 1
//   - SH    (bits [9:8]):   Shareability — identical position to Stage 1
//
// All positions verified from:
//   linux-ref/arch/arm64/include/asm/kvm_pgtable.h lines 67–100
//   linux-ref/arch/arm64/include/asm/memory.h lines 182–184
// ─────────────────────────────────────────────────────────────────────────────

/// Stage 2 page table descriptor attribute constants.
///
/// Sources:
/// - `kvm_pgtable.h` lines 79–84 for S2AP, MemAttr, SH, AF positions
/// - `memory.h` lines 182–184 for MemAttr encoding values
pub mod stage2 {
    // ── Access permissions (S2AP) — bits [7:6] ────────────────────────────
    //
    // Source: kvm_pgtable.h line 80: `KVM_PTE_LEAF_ATTR_LO_S2_S2AP_R BIT(6)`
    //         kvm_pgtable.h line 81: `KVM_PTE_LEAF_ATTR_LO_S2_S2AP_W BIT(7)`
    //
    // S2AP encoding:
    //   0b00 = No access (fault on any access)
    //   0b01 = Read-only (S2AP_R only)
    //   0b10 = Write-only (S2AP_W only)
    //   0b11 = Read+Write (both bits)

    /// Bit 6: S2AP_R — Stage 2 read permission bit.
    /// Source: kvm_pgtable.h line 80
    pub const S2AP_R: u64 = 1 << 6;

    /// Bit 7: S2AP_W — Stage 2 write permission bit.
    /// Source: kvm_pgtable.h line 81
    pub const S2AP_W: u64 = 1 << 7;

    /// Read+Write access: both S2AP_R and S2AP_W set.
    pub const S2AP_RW: u64 = S2AP_R | S2AP_W;

    // ── Memory attributes (MemAttr) — bits [5:2] ──────────────────────────
    //
    // MemAttr is a 4-bit encoding of memory type. It is NOT an index into
    // MAIR_EL1 — that is Stage 1. Stage 2 has its own independent encoding.
    //
    // Source: memory.h lines 182–184 (MT_S2_* constants)
    // Encoding reference: ARM ARM DDI0487 Table D5-51

    /// MemAttr field shift (bits [5:2]).
    /// Source: kvm_pgtable.h line 79: `KVM_PTE_LEAF_ATTR_LO_S2_MEMATTR GENMASK(5, 2)`
    pub const MEMATTR_SHIFT: u32 = 2;

    /// MemAttr = 0xF: Normal memory, Inner/Outer Write-Back Write-Allocate Cacheable.
    /// This is the standard memory type for RAM — Android's code and heap regions.
    /// Source: memory.h line 182 `#define MT_S2_NORMAL 0xf`
    pub const MEMATTR_NORMAL: u64 = 0xF << MEMATTR_SHIFT;

    /// MemAttr = 0x1: Device memory, nGnRE (non-Gathering, non-Reordering, Early-ack).
    /// Used for MMIO regions mapped into the Android partition for device passthrough.
    /// Source: memory.h line 184 `#define MT_S2_DEVICE_nGnRE 0x1`
    /// The lowercase `nGnRE` is the ARM architecture's own abbreviation — allow it.
    #[allow(non_upper_case_globals)]
    pub const MEMATTR_DEVICE_nGnRE: u64 = 0x1 << MEMATTR_SHIFT;

    /// MemAttr = 0x5: Normal Non-Cacheable.
    /// Used for DMA-coherent buffers that must not be cached.
    /// Source: memory.h line 183 `#define MT_S2_NORMAL_NC 0x5`
    pub const MEMATTR_NORMAL_NC: u64 = 0x5 << MEMATTR_SHIFT;

    // ── Shareability (SH) — bits [9:8] ────────────────────────────────────
    //
    // Source: kvm_pgtable.h line 82: `KVM_PTE_LEAF_ATTR_LO_S2_SH GENMASK(9, 8)`
    //         kvm_pgtable.h line 83: `KVM_PTE_LEAF_ATTR_LO_S2_SH_IS 3`

    /// SH = 0b11: Inner Shareable. Standard for Normal memory pages.
    /// Source: kvm_pgtable.h line 83
    pub const SH_INNER: u64 = 0b11 << 8;

    // ── Access Flag (AF) — bit [10] ────────────────────────────────────────
    //
    // Source: kvm_pgtable.h line 84: `KVM_PTE_LEAF_ATTR_LO_S2_AF BIT(10)`

    /// Bit 10: AF — Access Flag. Must be 1 on initial mapping to avoid access
    /// flag faults on first access (AETHER manages AF in software for simplicity).
    /// Source: kvm_pgtable.h line 84
    pub const AF: u64 = 1 << 10;

    // ── Execute-never (XN) — bits [54:53] ─────────────────────────────────
    //
    // Stage 2 XN is a 2-bit field: bit 53 = XN for EL1, bit 54 = XN for EL0.
    // Source: kvm_pgtable.h line 94:
    //   `KVM_PTE_LEAF_ATTR_HI_S2_XN GENMASK(54, 53)`

    /// Bits [54:53]: XN — Execute-never for both EL1 and EL0.
    /// Used for all data/MMIO pages.
    pub const XN_ALL: u64 = 0b11 << 53;

    // ── Descriptor type bits [1:0] ─────────────────────────────────────────
    //
    // ARM ARM DDI0487 Table D5-1: descriptor type encoding is identical to Stage 1.
    //   0b01 = Block descriptor (maps a large contiguous region)
    //   0b11 = Page/Table descriptor
    //   0b00 or 0b10 = Invalid

    /// Bits [1:0] = 0b11: Valid page (4KB leaf) descriptor.
    pub const DESC_PAGE: u64 = 0b11;

    /// Bits [1:0] = 0b01: Valid block (2MB leaf) descriptor.
    pub const DESC_BLOCK: u64 = 0b01;

    /// Bits [1:0] = 0b11 at a non-leaf level: table descriptor (pointer to next level).
    pub const DESC_TABLE: u64 = 0b11;

    // ── Composite attribute sets for common use cases ──────────────────────

    /// Attributes for a normal R/W RAM page: cacheable, inner-shareable, R+W, AF set.
    pub const NORMAL_PAGE_RW: u64 = DESC_PAGE | MEMATTR_NORMAL | SH_INNER | AF | S2AP_RW;

    /// Attributes for a normal read-only RAM page (e.g., guest kernel text after boot).
    pub const NORMAL_PAGE_RO: u64 = DESC_PAGE | MEMATTR_NORMAL | SH_INNER | AF | S2AP_R;

    /// Attributes for a Device MMIO page: non-cacheable, execute-never, R+W.
    pub const DEVICE_PAGE_RW: u64 = DESC_PAGE | MEMATTR_DEVICE_nGnRE | AF | S2AP_RW | XN_ALL;
}

// ─────────────────────────────────────────────────────────────────────────────
// CPTR_EL2 — Architectural Feature Trap Register
//
// Controls whether FP/SIMD, SVE, and other architectural features at EL1/EL0
// trap to EL2. AETHER must NOT trap FP/SIMD: Android uses NEON/FP heavily
// for multimedia, gaming, and JIT-compiled code.
//
// nVHE mode CPTR_EL2 layout (E2H=0):
//   Bits [13,9,7:0] are RES1 — must be written 1.
//   Bit 10 (TFP): 0 = FP/SIMD does NOT trap to EL2 (correct for AETHER).
//   Bit 12 (TSM): 0 = SME does NOT trap (AETHER neither uses nor traps SME).
//   Bit 20 (TTA): 0 = system instruction tracing does not trap.
//   Bit 30 (TAM): 0 = Activity Monitor does not trap.
//   Bit 31 (TCPAC): 0 = CPACR_EL1/CPTR_EL2 access does not trap.
//
// Source: linux-ref/arch/arm64/include/asm/kvm_arm.h line 278
//   `CPTR_NVHE_EL2_RES1 = BIT(13) | BIT(9) | GENMASK(7, 0)`
//   = 0x2000 | 0x0200 | 0x00FF = 0x22FF
// ─────────────────────────────────────────────────────────────────────────────

/// CPTR_EL2 constants for nVHE mode.
///
/// Source: `linux-ref/arch/arm64/include/asm/kvm_arm.h` line 278.
pub mod cptr_el2 {
    /// RES1 bits for nVHE mode: BIT(13) | BIT(9) | GENMASK(7, 0).
    /// Must be written 1. Writing 0 to these is UNPREDICTABLE.
    /// Source: kvm_arm.h line 278
    pub const NVHE_RES1: u64 = (1 << 13) | (1 << 9) | 0xFF;

    /// TFP (bit 10): Trap FP/SIMD instructions at EL1/EL0.
    /// AETHER keeps this CLEAR (0) so Android's FP/SIMD runs at full speed.
    /// Source: kvm_arm.h line 276
    pub const TFP: u64 = 1 << 10;

    /// CPTR_EL2 value for AETHER: RES1 bits set, TFP clear, all other traps clear.
    /// Android sees full FP/SIMD access at EL1/EL0.
    pub const AETHER_CONFIG: u64 = NVHE_RES1;
    // Note: TFP is deliberately NOT included — trapping FP/SIMD is not wanted.
}

// ─────────────────────────────────────────────────────────────────────────────
// GIC Virtualization Extension
//
// The ARM Generic Interrupt Controller v3 includes a Virtualization Extension
// (GICv3 spec IHI0069, Chapter 8) that allows the hypervisor to inject virtual
// interrupts directly into a guest vCPU without software involvement on every
// interrupt delivery.
//
// Key registers at EL2:
//   ICH_HCR_EL2:  Hypervisor Control Register — enables the virt extension
//   ICH_LR{n}_EL2: List Registers — program interrupts to inject
//   ICH_VTR_EL2:  VGIC Type Register — number of LRs and priority bits (RO)
//
// Chapter 6 implements the stubs and constants.
// Full interrupt routing is Chapter 10 (interrupt-routing.md).
//
// ICH_LR layout (64-bit, each LR programs one virtual interrupt):
//   bits [31:0]  — vINTID: Virtual interrupt ID (0–1019 for SGIs/PPIs/SPIs)
//   bits [41:32] — pINTID: Physical interrupt ID (for HW-mapped interrupts)
//   bit  [41]    — EOI:    Maintenance interrupt on deactivation
//   bits [55:48] — Priority: Virtual interrupt priority
//   bit  [60]    — Group:  0 = Group 0, 1 = Group 1
//   bit  [61]    — HW:     1 = hardware-backed interrupt (pINTID valid)
//   bits [63:62] — State:  00=Invalid, 01=Pending, 10=Active, 11=Active+Pending
//
// Sources: linux-ref/arch/arm64/include/asm/sysreg.h lines 970–981
//          linux-ref/arch/arm64/tools/sysreg lines 5143–5163
// ─────────────────────────────────────────────────────────────────────────────

/// GIC Virtualization Extension register constants.
///
/// Sources:
/// - `sysreg.h` lines 970–981 for ICH_LR field masks
/// - `sysreg` tool lines 5143–5163 for ICH_HCR_EL2 fields
pub mod gic_virt {
    // ── ICH_HCR_EL2 — Hypervisor Control Register ─────────────────────────
    //
    // Source: linux-ref/arch/arm64/tools/sysreg lines 5143–5163

    /// ICH_HCR_EL2 bit 0: En — Enable GIC virtualization extension.
    /// Must be 1 before entering a guest that uses virtual interrupts.
    /// Source: sysreg line 5162 `Field 0 En`
    pub const ICH_HCR_EN: u64 = 1 << 0;

    /// ICH_HCR_EL2 bit 1: UIE — Underflow Interrupt Enable.
    /// Generates maintenance interrupt when fewer than 2 LRs are active.
    /// AETHER leaves this 0 (uses polling model in early chapters).
    /// Source: sysreg line 5161 `Field 1 UIE`
    pub const ICH_HCR_UIE: u64 = 1 << 1;

    /// ICH_HCR_EL2 bit 2: LRENPIE — List Register Entry Not Present Interrupt Enable.
    /// Source: sysreg line 5160 `Field 2 LRENPIE`
    pub const ICH_HCR_LRENPIE: u64 = 1 << 2;

    /// ICH_HCR_EL2 bit 3: NPIE — No Pending Interrupt Enable.
    /// Source: sysreg line 5159 `Field 3 NPIE`
    pub const ICH_HCR_NPIE: u64 = 1 << 3;

    // ── ICH_LR (List Register) field layout ────────────────────────────────
    //
    // Source: linux-ref/arch/arm64/include/asm/sysreg.h lines 970–981

    /// Mask for vINTID field: bits [31:0].
    /// Source: sysreg.h line 970 `ICH_LR_VIRTUAL_ID_MASK = (1ULL << 32) - 1`
    pub const ICH_LR_VIRTUAL_ID_MASK: u64 = (1u64 << 32) - 1;

    /// Bit 41: EOI — maintenance interrupt when the LR transitions to Invalid.
    /// Source: sysreg.h line 972 `ICH_LR_EOI = (1ULL << 41)`
    pub const ICH_LR_EOI: u64 = 1 << 41;

    /// pINTID field shift (bits [41:32]).
    /// Source: sysreg.h line 978 `ICH_LR_PHYS_ID_SHIFT = 32`
    pub const ICH_LR_PHYS_ID_SHIFT: u32 = 32;

    /// pINTID field mask (10-bit physical interrupt ID at bits [41:32]).
    /// Source: sysreg.h line 979 `ICH_LR_PHYS_ID_MASK = (0x3ffULL << ICH_LR_PHYS_ID_SHIFT)`
    pub const ICH_LR_PHYS_ID_MASK: u64 = 0x3FF << ICH_LR_PHYS_ID_SHIFT;

    /// Priority field shift (bits [55:48]).
    /// Source: sysreg.h line 980 `ICH_LR_PRIORITY_SHIFT = 48`
    pub const ICH_LR_PRIORITY_SHIFT: u32 = 48;

    /// Priority field mask (8-bit priority at bits [55:48]).
    /// Source: sysreg.h line 981 `ICH_LR_PRIORITY_MASK = (0xffULL << ICH_LR_PRIORITY_SHIFT)`
    pub const ICH_LR_PRIORITY_MASK: u64 = 0xFF << ICH_LR_PRIORITY_SHIFT;

    /// Bit 60: Group — 0 = Group 0, 1 = Group 1 interrupt.
    /// Source: sysreg.h line 973 `ICH_LR_GROUP = (1ULL << 60)`
    pub const ICH_LR_GROUP: u64 = 1 << 60;

    /// Bit 61: HW — Hardware-backed interrupt. When set, pINTID is valid and
    /// the GIC automatically deactivates the physical interrupt on guest EOI.
    /// Source: sysreg.h line 974 `ICH_LR_HW = (1ULL << 61)`
    pub const ICH_LR_HW: u64 = 1 << 61;

    /// Bits [63:62]: State field. Encodes the LR state machine:
    ///   0b00 = Invalid (LR is unused)
    ///   0b01 = Pending (interrupt waiting for delivery)
    ///   0b10 = Active  (interrupt acknowledged, handler running)
    ///   0b11 = Active+Pending (re-triggered while handler running)
    /// Source: sysreg.h line 975 `ICH_LR_STATE = (3ULL << 62)`
    pub const ICH_LR_STATE: u64 = 3 << 62;

    /// Bit 62: Pending state bit.
    /// Source: sysreg.h line 976 `ICH_LR_PENDING_BIT = (1ULL << 62)`
    pub const ICH_LR_PENDING_BIT: u64 = 1 << 62;

    /// Bit 63: Active state bit.
    /// Source: sysreg.h line 977 `ICH_LR_ACTIVE_BIT = (1ULL << 63)`
    pub const ICH_LR_ACTIVE_BIT: u64 = 1 << 63;

    /// Build a pending LR value for a software virtual interrupt (no HW backing).
    ///
    /// Programs one List Register to deliver a Group 1 virtual interrupt
    /// with the given vINTID and priority. The interrupt will be delivered to
    /// the guest vCPU when it next runs with PSTATE.I clear.
    ///
    /// # Arguments
    /// - `vintid`: Virtual interrupt ID (SGI 0–15, PPI 16–31, SPI 32–1019)
    /// - `priority`: 8-bit priority (lower = higher priority; 0x00 = highest)
    #[inline]
    pub const fn build_pending_sw(vintid: u32, priority: u8) -> u64 {
        let vid = (vintid as u64) & ICH_LR_VIRTUAL_ID_MASK;
        let prio = (priority as u64) << ICH_LR_PRIORITY_SHIFT;
        vid | prio | ICH_LR_GROUP | ICH_LR_PENDING_BIT
    }

    /// Build a pending LR value for a hardware-backed virtual interrupt.
    ///
    /// When HW=1, the physical interrupt with `pintid` is automatically
    /// deactivated in the GIC when the guest issues an EOI for `vintid`.
    /// This is the preferred model for device interrupts routed to Android.
    ///
    /// # Arguments
    /// - `vintid`: Virtual interrupt ID presented to the Android guest
    /// - `pintid`: Physical interrupt ID in the GIC distributor (10-bit)
    /// - `priority`: 8-bit priority
    #[inline]
    pub const fn build_pending_hw(vintid: u32, pintid: u16, priority: u8) -> u64 {
        let vid = (vintid as u64) & ICH_LR_VIRTUAL_ID_MASK;
        let pid = ((pintid as u64) << ICH_LR_PHYS_ID_SHIFT) & ICH_LR_PHYS_ID_MASK;
        let prio = (priority as u64) << ICH_LR_PRIORITY_SHIFT;
        vid | pid | prio | ICH_LR_GROUP | ICH_LR_HW | ICH_LR_PENDING_BIT
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EL2 Virtualization initialization
//
// Called once during AETHER boot, after install_vectors() (Chapter 5) and
// before the first guest entry (Chapter 7).
//
// Register write sequence:
//   1. CPTR_EL2   — disable FP/SIMD traps; RES1 bits required
//   2. VTCR_EL2   — Stage 2 translation parameters
//   3. VTTBR_EL2  — Stage 2 table base + VMID
//   4. TLBI VMALLS12E1IS + DSB ISH + ISB — flush stale Stage 1+2 TLBs
//   5. ICH_HCR_EL2.En — enable GIC virtualization extension
//
// HCR_EL2 with GUEST_FLAGS (including VM=1) is written here, after VTTBR_EL2
// is set and TLBs are flushed. VM=1 only affects EL1/EL0 accesses — EL2
// hypervisor code is unaffected. Stage 2 tables must be populated first
// (done in main.rs steps 5 before this call).
//
// TLB invalidation rationale:
//   TLBI VMALLS12E1IS = invalidate all Stage 1 AND Stage 2 TLB entries
//     for the current VMID in the Inner Shareable domain.
//   This is the correct instruction to use after changing VTTBR_EL2.
//   It is NOT the same as TLBI ALLE2 (which only clears EL2 entries).
//   Skill guide warning: confusing these two is a common AI mistake.
//   DSB ISH before TLBI: ensures prior writes are visible before invalidation.
//   ISB after TLBI: ensures the invalidation completes before next instruction fetch.
// ─────────────────────────────────────────────────────────────────────────────

/// Initialize EL2 virtualization registers for the Android guest.
///
/// Sets CPTR_EL2, VTCR_EL2, VTTBR_EL2, flushes TLBs, and enables
/// the GIC virtualization extension. Must be called from EL2 before
/// the first guest entry.
///
/// # Safety
/// - Must be called from EL2.
/// - `s2_root_pa` must be the physical address of a valid, zeroed Stage 2
///   Level 1 page table, aligned to at least 8KiB
///   (2^x bytes where x = IPA_BITS − 9*levels = 40 − 27 = 13).
/// - No guest must be running when this is called.
pub unsafe fn configure_el2_virt(s2_root_pa: u64) {
    // ── Step 1: CPTR_EL2 — allow FP/SIMD at EL1/EL0, write RES1 bits ─────
    unsafe {
        asm!(
            "msr cptr_el2, {cptr}",
            "isb",
            cptr = in(reg) cptr_el2::AETHER_CONFIG,
            options(nomem, nostack, preserves_flags),
        );
    }

    // ── Step 2: VTCR_EL2 — Stage 2 translation parameters ─────────────────
    // 40-bit IPA, 4KB granule, Level 1 start, 48-bit PA, 8-bit VMID, RES1 set.
    unsafe {
        asm!(
            "msr vtcr_el2, {vtcr}",
            vtcr = in(reg) vtcr_el2::CONFIG,
            options(nomem, nostack, preserves_flags),
        );
    }

    // ── Step 3: VTTBR_EL2 — Stage 2 table base address + VMID ─────────────
    let vttbr = vttbr_el2::build(vttbr_el2::VMID_ANDROID, s2_root_pa);
    unsafe {
        asm!(
            "msr vttbr_el2, {vttbr}",
            vttbr = in(reg) vttbr,
            options(nomem, nostack, preserves_flags),
        );
    }

    // ── Step 4: Flush Stage 1 + Stage 2 TLBs for the Android VMID ─────────
    //
    // Sequence: DSB ISH → TLBI VMALLS12E1IS → DSB ISH → ISB
    //
    // DSB ISH before TLBI ensures all previous writes (VTTBR_EL2) are
    // visible to the TLB hardware before invalidation begins.
    // DSB ISH after TLBI waits for the invalidation to complete.
    // ISB after DSB ensures the next instruction sees the clean TLB.
    //
    // TLBI VMALLS12E1IS chosen because:
    //   - VMALLS12 = "all entries for all VMIDs, Stage 1 and Stage 2"
    //   - IS = Inner Shareable domain (all cores see the invalidation)
    // This is correct at EL2 when VTTBR_EL2 changes.
    // Reference: ARM ARM DDI0487 section C5.5 (TLBI encodings)
    dsb_ish();
    unsafe {
        asm!(
            "tlbi vmalls12e1is",
            options(nomem, nostack, preserves_flags),
        );
    }
    dsb_ish();
    isb();

    // ── Step 5: HCR_EL2 — enable Stage 2 and configure guest execution ──────
    // GUEST_FLAGS: VM=1 activates Stage 2 translation for EL1/EL0.
    // RW=1 ensures lower EL is AArch64. FMO/IMO/AMO route exceptions to EL2.
    // ISB required after writing HCR_EL2 to ensure the change takes effect
    // before any subsequent EL1 activity.
    unsafe {
        asm!(
            "msr hcr_el2, {hcr}",
            "isb",
            hcr = in(reg) hcr_el2::GUEST_FLAGS,
            options(nomem, nostack, preserves_flags),
        );
    }

    // ── Step 6: ICH_HCR_EL2 — Enable GIC virtualization extension ──────────
    // Setting En=1 activates the virtual CPU interface so the GIC can deliver
    // virtual interrupts to the Android guest without hypervisor intervention
    // on each interrupt delivery.
    // Chapter 10 will add UIE/LRENPIE for maintenance interrupt handling.
    unsafe {
        asm!(
            "msr ich_hcr_el2, {ich_hcr}",
            ich_hcr = in(reg) gic_virt::ICH_HCR_EN,
            options(nomem, nostack, preserves_flags),
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Compile-time constant verification
//
// These assertions verify the computed VTCR_EL2 configuration value and that
// our Stage 2 attribute constants have the expected numeric values.
// ─────────────────────────────────────────────────────────────────────────────

const _: () = {
    // VTCR_EL2 CONFIG numerical verification.
    // Expected: T0SZ=24 | SL0=1<<6 | IRGN0=1<<8 | ORGN0=1<<10 |
    //           SH0=3<<12 | TG0=0<<14 | PS=5<<16 | VS=0 | RES1=1<<31
    //   = 0x18 | 0x40 | 0x100 | 0x400 | 0x3000 | 0 | 0x50000 | 0 | 0x80000000
    //   = 0x8005_3558
    assert!(
        vtcr_el2::CONFIG == 0x8005_3558,
        "VTCR_EL2::CONFIG must be 0x8005_3558 for 40-bit IPA, 4KB granule, 48-bit PA"
    );

    // MT_S2_NORMAL = 0xF — innermost 4 bits of MemAttr, shifted by MEMATTR_SHIFT=2
    // → 0xF << 2 = 0x3C
    assert!(
        stage2::MEMATTR_NORMAL == 0x3C,
        "MEMATTR_NORMAL must be 0x3C (MT_S2_NORMAL=0xF << 2)"
    );

    // MT_S2_DEVICE_nGnRE = 0x1 shifted left 2 = 0x4
    assert!(
        stage2::MEMATTR_DEVICE_nGnRE == 0x4,
        "MEMATTR_DEVICE_nGnRE must be 0x4 (MT_S2_DEVICE_nGnRE=0x1 << 2)"
    );

    // VTTBR VMID_SHIFT must be 48
    assert!(
        vttbr_el2::VMID_SHIFT == 48,
        "VTTBR_EL2 VMID_SHIFT must be 48"
    );

    // CPTR_NVHE_EL2_RES1 = BIT(13)|BIT(9)|GENMASK(7,0) = 0x2000|0x200|0xFF = 0x22FF
    assert!(
        cptr_el2::NVHE_RES1 == 0x22FF,
        "CPTR_EL2 NVHE_RES1 must be 0x22FF (BIT(13)|BIT(9)|GENMASK(7,0))"
    );

    // HCR_EL2 GUEST_FLAGS: verify a few key bits are present
    assert!(
        hcr_el2::GUEST_FLAGS & hcr_el2::VM != 0,
        "GUEST_FLAGS must include VM bit"
    );
    assert!(
        hcr_el2::GUEST_FLAGS & hcr_el2::RW != 0,
        "GUEST_FLAGS must include RW bit (64-bit EL1)"
    );
    assert!(
        hcr_el2::GUEST_FLAGS & (1 << 34) == 0,
        "GUEST_FLAGS must NOT include E2H (nVHE mode)"
    );
};
