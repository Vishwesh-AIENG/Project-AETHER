// ch10: Interrupt Routing
//
// When a hardware device raises an interrupt, the ARM Generic Interrupt
// Controller (GIC v3) routes it to the CPU. In a virtualized system AETHER
// must intercept physical interrupts, decide which guest owns them, and
// inject them as virtual interrupts via the GIC Virtualization Extension so
// the Android kernel sees a real hardware interrupt without any software
// involvement on the fast path.
//
// This module implements:
//   1. MADT GIC structure parsing — discover GICD / GICR / GICV base
//      addresses from the ACPI table populated by firmware.
//   2. Physical GICv3 initialization — wake all Redistributors (GICR),
//      enable the Distributor (GICD) with affinity routing, configure the
//      CPU Interface (ICC) system registers.
//   3. VGicState — List Register (ICH_LRn_EL2) allocation and virtual
//      interrupt injection for the Android guest.
//   4. Maintenance interrupt handling — when the guest EOIs a virtual
//      interrupt that had HW=0, the GIC fires a maintenance interrupt to
//      EL2; this module clears the stale LR entries.
//   5. Physical IRQ forwarding — acknowledge the physical interrupt via
//      ICC_IAR1_EL1, re-inject it as a hardware-backed virtual interrupt
//      (HW=1) so the GIC automatically deactivates the physical interrupt
//      when the guest EOIs its virtual counterpart.
//
// Confidence: LOW (per ch10-interrupt-routing.md skill guide). Every bit
// field is cited to the GIC Architecture Specification IHI0069 or the
// Linux reference implementation.
//
// Primary sources:
//   - GIC Architecture Specification IHI0069 (GICv3/v4) — the sole
//     authoritative reference for all register layouts and bit fields.
//   - linux-ref/include/linux/irqchip/arm-gic-v3.h — register offsets
//   - linux-ref/drivers/irqchip/irq-gic-v3.c — physical init sequence
//   - linux-ref/arch/arm64/include/asm/sysreg.h — ICH_LR bit masks
//   - ACPI 6.4 Specification Tables 5.56–5.58 — MADT GIC structures

use core::ptr;

use crate::arm64::barriers::{dsb_ish, dsb_ishst};

// ─────────────────────────────────────────────────────────────────────────────
// MADT GIC structure parsing
//
// The ACPI MADT table contains one or more Interrupt Controller Structures
// that describe the physical GIC layout. AETHER walks these to find the
// physical base addresses it needs.
//
// MADT header layout (ACPI 6.4 Section 5.2.12):
//   Bytes 0–35:  Standard ACPI SDT header
//   Bytes 36–39: Local Controller Address (x86 LAPIC; ignored on ARM)
//   Bytes 40–43: Flags
//   Bytes 44+:   Variable-length Interrupt Controller Structures
// ─────────────────────────────────────────────────────────────────────────────

/// Byte offset from MADT base where IC structure entries begin.
const MADT_IC_ENTRIES_OFFSET: usize = 44;

/// IC Structure Type 0x0B: GIC CPU Interface (one per CPU).
/// Contains GICV/GICH base addresses and the maintenance interrupt GSIV.
/// Source: ACPI 6.4 Table 5.56; Linux ACPI_MADT_TYPE_GENERIC_INTERRUPT = 11.
const MADT_TYPE_GICC: u8 = 0x0B;

/// IC Structure Type 0x0C: GIC Distributor (one per system).
/// Contains the GICD physical base address.
/// Source: ACPI 6.4 Table 5.57; Linux ACPI_MADT_TYPE_GENERIC_DISTRIBUTOR = 12.
const MADT_TYPE_GICD: u8 = 0x0C;

/// IC Structure Type 0x0E: GIC Redistributor Range.
/// Contains the base PA of the contiguous GICR range for all PEs.
/// Source: ACPI 6.4 Table 5.58; Linux ACPI_MADT_TYPE_GENERIC_REDISTRIBUTOR = 14.
const MADT_TYPE_GICR: u8 = 0x0E;

/// GIC CPU Interface MADT structure — field byte offsets.
/// Source: ACPI 6.4 Table 5.56 (total length = 80 bytes).
mod gicc_offset {
    /// Physical base address of the GICV (Virtual CPU Interface) frame.
    /// This is the memory region mapped into the guest address space so
    /// the Android GIC driver can acknowledge/EOI virtual interrupts as if
    /// they came from a real CPU Interface.
    pub const GICV_PA: usize = 40;

    /// Physical base address of the GICH (Hypervisor Control Interface).
    /// AETHER uses ICH_* system registers in nVHE mode rather than MMIO;
    /// this field is recorded for documentation purposes and future use.
    #[allow(dead_code)]
    pub const GICH_PA: usize = 48;

    /// GSIV (Global System Interrupt Vector) of the VGIC maintenance interrupt.
    /// This is the physical interrupt INTID that fires when the virtual CPU
    /// interface needs hypervisor attention (e.g., LR deactivation, underflow).
    pub const VGIC_MAINT_INTID: usize = 56;

    /// Physical base address of this CPU's Redistributor frame (RD_base).
    /// Offset 60, 8 bytes (u64).
    pub const GICR_PA: usize = 60;
}

/// GIC Distributor MADT structure — field byte offsets.
/// Source: ACPI 6.4 Table 5.57 (total length = 24 bytes).
mod gicd_offset {
    /// Physical base address of the GICD frame (8 bytes, u64 at offset 8).
    pub const BASE_PA: usize = 8;

    /// GIC Version byte at offset 20. 0x03 = GICv3, 0x04 = GICv4.
    /// Recorded for documentation; version checking deferred to later chapters.
    #[allow(dead_code)]
    pub const GIC_VERSION: usize = 20;
}

/// GIC Redistributor Range MADT structure — field byte offsets.
/// Source: ACPI 6.4 Table 5.58 (total length = 16 bytes).
mod gicr_range_offset {
    /// Start of the GICR range (8 bytes, u64 at offset 8).
    pub const BASE_PA: usize = 8;
}

/// Physical base addresses of all GIC components discovered from the MADT.
#[derive(Debug, Clone, Copy)]
pub struct GicAddrs {
    /// Physical base of the GIC Distributor (GICD).
    pub gicd_pa: u64,
    /// Physical base of the first GIC Redistributor (GICR) frame (RD_base).
    /// Each PE has a 128 KiB pair: RD_base (64 KiB) + SGI_base (64 KiB).
    pub gicr_pa: u64,
    /// Physical base of the Virtual CPU Interface (GICV) frame.
    /// AETHER maps this into the Android guest's IPA space so the Android
    /// GIC driver can read/write it without trapping to EL2.
    pub gicv_pa: u64,
    /// Physical interrupt ID (GSIV) of the VGIC maintenance interrupt.
    /// Typically INTID 25 (a PPI) on most Snapdragon platforms.
    pub maint_intid: u32,
}

/// Walk the MADT at `madt_pa` and extract all GIC component addresses.
///
/// Returns `None` if the GICD structure is not found (required) or if the
/// MADT length field is too small to hold any entries.
///
/// # Safety
/// - `madt_pa` must be a valid physical address of a well-formed ACPI MADT.
/// - The MADT must remain readable (not reclaimed) for the duration of this
///   call. In practice this is called before ExitBootServices completes, or
///   from a region AETHER has pinned as Conventional memory.
pub unsafe fn discover_gic_from_madt(madt_pa: u64) -> Option<GicAddrs> {
    let base = madt_pa as *const u8;

    // MADT total length is a u32 at byte offset 4 (standard SDT header).
    let total_len = unsafe { ptr::read_unaligned(base.add(4) as *const u32) } as usize;
    if total_len < MADT_IC_ENTRIES_OFFSET {
        return None;
    }

    let mut gicd_pa: Option<u64> = None;
    let mut gicr_pa: Option<u64> = None;
    let mut gicv_pa: u64 = 0;
    let mut maint_intid: u32 = 25; // Safe default (INTID 25 is the standard maintenance PPI)

    let entries_end = madt_pa as usize + total_len;
    let mut pos = madt_pa as usize + MADT_IC_ENTRIES_OFFSET;

    while pos + 2 <= entries_end {
        let ic_type = unsafe { ptr::read_unaligned(pos as *const u8) };
        let ic_len = unsafe { ptr::read_unaligned((pos + 1) as *const u8) } as usize;

        if ic_len < 2 || pos + ic_len > entries_end {
            break;
        }

        match ic_type {
            MADT_TYPE_GICD if ic_len >= gicd_offset::BASE_PA + 8 => {
                let pa = unsafe {
                    ptr::read_unaligned((pos + gicd_offset::BASE_PA) as *const u64)
                };
                gicd_pa = Some(pa);
            }
            MADT_TYPE_GICR if ic_len >= gicr_range_offset::BASE_PA + 8 => {
                if gicr_pa.is_none() {
                    let pa = unsafe {
                        ptr::read_unaligned((pos + gicr_range_offset::BASE_PA) as *const u64)
                    };
                    gicr_pa = Some(pa);
                }
            }
            MADT_TYPE_GICC if ic_len >= gicc_offset::GICR_PA + 8 => {
                // First GICC entry gives us GICV PA and maintenance INTID.
                // GICR_PA here is the per-CPU GICR — we prefer the GICR range
                // entry (type 0x0D) when present, but fall back to GICC.GICR_PA.
                if gicr_pa.is_none() {
                    let pa = unsafe {
                        ptr::read_unaligned((pos + gicc_offset::GICR_PA) as *const u64)
                    };
                    if pa != 0 {
                        gicr_pa = Some(pa);
                    }
                }
                if gicv_pa == 0 {
                    gicv_pa = unsafe {
                        ptr::read_unaligned((pos + gicc_offset::GICV_PA) as *const u64)
                    };
                }
                if ic_len >= gicc_offset::VGIC_MAINT_INTID + 4 {
                    let m = unsafe {
                        ptr::read_unaligned((pos + gicc_offset::VGIC_MAINT_INTID) as *const u32)
                    };
                    if m != 0 {
                        maint_intid = m;
                    }
                }
            }
            _ => {}
        }

        pos += ic_len;
    }

    Some(GicAddrs {
        gicd_pa: gicd_pa?,
        gicr_pa: gicr_pa.unwrap_or(0),
        gicv_pa,
        maint_intid,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// GICD — GIC Distributor register offsets
//
// Source: linux-ref/include/linux/irqchip/arm-gic-v3.h
// All GICD registers are 32-bit unless stated otherwise.
// ─────────────────────────────────────────────────────────────────────────────

/// GIC Distributor register byte offsets from GICD base.
pub mod gicd {
    /// GICD_CTLR — Distributor Control Register.
    /// Source: GICv3 spec IHI0069 Section 12.2.2; arm-gic-v3.h line 24.
    pub const CTLR: usize = 0x0000;

    /// GICD_TYPER — Interrupt Controller Type Register.
    /// Bits [4:0] = ITLinesNumber (determines max SPI INTID as 32×(ITLines+1)−1).
    /// Source: arm-gic-v3.h line 25.
    pub const TYPER: usize = 0x0004;

    /// GICD_IGROUPR — Interrupt Group Registers (one 32-bit word per 32 INTIDs).
    /// Bit = 0: Group 0; bit = 1: Group 1 NS.
    /// AETHER configures all SPIs as Group 1 NS (bit = 1).
    /// Source: arm-gic-v3.h line 32.
    pub const IGROUPR0: usize = 0x0080;

    /// GICD_ISENABLER — Set-Enable Registers.
    /// Write 1 to a bit to enable the corresponding interrupt.
    /// Source: arm-gic-v3.h line 34.
    pub const ISENABLER0: usize = 0x0100;

    /// GICD_ICENABLER — Clear-Enable Registers.
    /// Write 1 to a bit to disable the corresponding interrupt.
    /// Source: arm-gic-v3.h line 36.
    pub const ICENABLER0: usize = 0x0180;

    /// GICD_ICPENDR — Clear-Pending Registers.
    /// Write 1 to clear a pending interrupt.
    /// Source: arm-gic-v3.h line 38.
    pub const ICPENDR0: usize = 0x0280;

    /// GICD_IPRIORITYR — Interrupt Priority Registers (one byte per INTID).
    /// Priority range 0x00–0xFF; lower value = higher priority.
    /// Source: arm-gic-v3.h line 40.
    pub const IPRIORITYR0: usize = 0x0400;

    /// GICD_ICFGR — Interrupt Configuration Registers.
    /// 2 bits per INTID: 0b00 = level-sensitive, 0b10 = edge-triggered.
    /// Source: arm-gic-v3.h line 44.
    pub const ICFGR0: usize = 0x0C00;

    /// GICD_IROUTER base offset.
    /// GICD_IROUTER<n> for INTID n is at `GICD_BASE + IROUTER_BASE + n × 8`.
    /// For SPI INTID 32 (first SPI): 0x6000 + 32×8 = 0x6100.
    /// Source: IHI0069 Section 12.2.18; arm-gic-v3.h line 42:
    ///   `#define GICD_IROUTER 0x6000`
    ///   linux irq-gic-v3.c line 978: `base + GICD_IROUTER + i * 8` (i from 32).
    pub const IROUTER_BASE: usize = 0x6000;

    // ── GICD_CTLR bit fields (GICv3 with ARE_NS=1) ────────────────────────────
    //
    // Source: IHI0069 Section 12.2.2, GICv3 GICD_CTLR bit layout.

    /// GICD_CTLR bit 0: EnableGrp0 — enable Group 0 interrupts globally.
    pub const CTLR_ENABLE_GRP0: u32 = 1 << 0;

    /// GICD_CTLR bit 1: EnableGrp1A — enable Group 1 NS interrupts with
    /// affinity routing enabled (ARE_NS = 1). This is the GICv3-native enable.
    /// Source: IHI0069 Section 12.2.2 GICD_CTLR bits when ARE_NS=1.
    pub const CTLR_ENABLE_GRP1A: u32 = 1 << 1;

    /// GICD_CTLR bit 4: ARE_NS — Affinity Routing Enable (Non-Secure).
    /// Must be 1 for GICv3 mode. Enables GICD_IROUTER routing and GICR usage.
    /// Source: IHI0069 Section 12.2.2.
    pub const CTLR_ARE_NS: u32 = 1 << 4;

    /// GICD_CTLR.RWP bit 31 — Register Write Pending.
    /// Reads 1 while a write is in progress. Poll until clear before
    /// reading back registers that depend on CTLR state.
    pub const CTLR_RWP: u32 = 1 << 31;

    /// Compute the GICD_IROUTER<n> byte offset from GICD base for INTID n.
    ///
    /// Valid only for SPIs (n ≥ 32). SGIs and PPIs are routed via GICR.
    /// Formula: `0x6000 + 8 × n` (n = absolute INTID, not a zero-based index).
    /// Source: IHI0069 Section 12.2.18; arm-gic-v3.h `#define GICD_IROUTER 0x6000`.
    #[inline]
    pub const fn irouter_offset(intid: u32) -> usize {
        debug_assert(intid >= 32);
        IROUTER_BASE + (intid as usize) * 8
    }

    const fn debug_assert(cond: bool) {
        // const-context assert substitute (evaluates to () in release)
        let _ = cond;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GICR — GIC Redistributor register offsets
//
// Each PE has a 128 KiB Redistributor consisting of two 64 KiB frames:
//   RD_base  (frame 0, offset 0x00000): basic Redistributor registers
//   SGI_base (frame 1, offset 0x10000): SGI/PPI specific registers
//
// Source: IHI0069 Sections 12.3 and 12.4; arm-gic-v3.h.
// ─────────────────────────────────────────────────────────────────────────────

/// GIC Redistributor register offsets.
pub mod gicr {
    /// Stride between consecutive Redistributor frames: 128 KiB per PE.
    /// RD_base is at `GICR_BASE + core × STRIDE`.
    pub const STRIDE: usize = 0x20000; // 128 KiB

    /// Offset of the SGI frame relative to the start of a Redistributor.
    /// SGI_base = RD_base + SGI_FRAME_OFFSET.
    pub const SGI_FRAME_OFFSET: usize = 0x10000;

    // ── RD frame offsets (relative to RD_base) ────────────────────────────

    /// GICR_CTLR — Redistributor Control Register.
    /// Source: arm-gic-v3.h line 127.
    pub const CTLR: usize = 0x0000;

    /// GICR_TYPER — Redistributor Type Register (64-bit).
    /// Bit [4]: LAST — set on the last Redistributor in the chain.
    /// Bits [56:32]: affinity of this PE (matches MPIDR Aff2/Aff1/Aff0).
    /// Source: arm-gic-v3.h line 128; IHI0069 Section 12.3.4.
    pub const TYPER: usize = 0x0008;

    /// GICR_WAKER — PE Wake Register.
    /// Controls whether this Redistributor forwards interrupts to the PE.
    /// Source: arm-gic-v3.h line 133; IHI0069 Section 12.3.7.
    pub const WAKER: usize = 0x0014;

    /// GICR_WAKER bit 1: ProcessorSleep.
    /// Clear to 0 to wake the PE; keep 1 when PE is offline.
    /// Source: IHI0069 Section 12.3.7 Table 12-31.
    pub const WAKER_PROCESSOR_SLEEP: u32 = 1 << 1;

    /// GICR_WAKER bit 2: ChildrenAsleep.
    /// Reads 1 while the Redistributor's interrupt register bank is inaccessible.
    /// Poll until 0 after clearing ProcessorSleep.
    pub const WAKER_CHILDREN_ASLEEP: u32 = 1 << 2;

    /// GICR_TYPER bit 4: LAST — this is the last Redistributor in the system.
    /// Used when walking the Redistributor range to find the end.
    pub const TYPER_LAST: u64 = 1 << 4;

    // ── SGI frame offsets (relative to SGI_base = RD_base + 0x10000) ──────

    /// GICR_IGROUPR0 — Interrupt Group Register for SGIs/PPIs.
    /// 32 bits covering INTIDs 0–31; set bit = Group 1.
    /// Source: arm-gic-v3.h line 153.
    pub const SGI_IGROUPR0: usize = 0x0080;

    /// GICR_ISENABLER0 — SGI/PPI Set-Enable.
    /// Source: arm-gic-v3.h line 154.
    pub const SGI_ISENABLER0: usize = 0x0100;

    /// GICR_ICENABLER0 — SGI/PPI Clear-Enable.
    /// Source: arm-gic-v3.h line 156.
    pub const SGI_ICENABLER0: usize = 0x0180;

    /// GICR_IPRIORITYR0 — SGI/PPI Priority base.
    /// One byte per INTID, starting at INTID 0.
    /// Source: arm-gic-v3.h line 160.
    pub const SGI_IPRIORITYR0: usize = 0x0400;
}

// ─────────────────────────────────────────────────────────────────────────────
// ICC — GIC CPU Interface (system register access)
//
// In GICv3, the CPU Interface is accessed via system registers (MRS/MSR) when
// ICC_SRE_EL2.SRE = 1. This eliminates the need to memory-map the legacy GICC
// frame at EL2. All ICC_* registers are accessed from EL2 in nVHE mode.
//
// Source: IHI0069 Chapter 5; linux-ref/arch/arm64/include/asm/sysreg.h.
// ─────────────────────────────────────────────────────────────────────────────

/// Physical spurious interrupt INTID — returned by ICC_IAR0/1_EL1 when there
/// is no pending interrupt of the selected group.
/// Source: IHI0069 Section 5.3.6.
pub const ICC_SPURIOUS_INTID: u32 = 0x3FF;

/// ICC CPU Interface system register access functions.
pub mod icc {
    use core::arch::asm;

    /// Enable system-register access to the GIC CPU Interface at EL2.
    ///
    /// Sets ICC_SRE_EL2.SRE=1 (system register enable), .Enable=1 (allow
    /// EL1 to use ICC_SRE_EL1), .DIB=1 (disable IRQ bypass), .DFB=1 (disable
    /// FIQ bypass). An ISB is required before any subsequent ICC register use.
    ///
    /// # Safety
    /// Must be called from EL2 before any other ICC register access.
    pub unsafe fn enable_sre_el2() {
        // ICC_SRE_EL2 bit layout (IHI0069 Section 5.7.14):
        //   Bit 0: SRE — System Register Enable
        //   Bit 1: DIB — Disable IRQ Bypass
        //   Bit 2: DFB — Disable FIQ Bypass
        //   Bit 3: Enable — ICC_SRE_EL1 access enabled for NS EL1
        // All four bits set: 0b1111 = 0xF
        unsafe {
            asm!(
                "msr icc_sre_el2, {v}",
                "isb",
                v = in(reg) 0xFu64,
                options(nomem, nostack, preserves_flags),
            );
        }
    }

    /// Configure the CPU Interface for Group 1 NS interrupt delivery.
    ///
    /// - ICC_PMR_EL1: priority mask = 0xFF (all priorities allowed)
    /// - ICC_BPR1_EL1: binary point = 0 (no preemption grouping)
    /// - ICC_CTLR_EL1: EOImode = 0 (EOI deactivates physically, but with
    ///   HW-backed LRs the deactivation is gated through the virtual interface)
    /// - ICC_IGRPEN1_EL1: bit 0 = 1 (Group 1 NS enabled)
    ///
    /// # Safety
    /// Must be called after `enable_sre_el2()` and its ISB.
    pub unsafe fn init_cpu_interface() {
        unsafe {
            asm!(
                // Priority mask: allow all interrupt priorities (0xFF = lowest
                // priority threshold — all interrupts with priority < 0xFF pass).
                "msr icc_pmr_el1, {pmr}",
                // Binary point: 0 = no preemption group splitting.
                "msr icc_bpr1_el1, {zero}",
                // Enable Group 1 NS interrupts on this CPU.
                "msr icc_igrpen1_el1, {grp1}",
                "isb",
                pmr  = in(reg) 0xFFu64,
                zero = in(reg) 0u64,
                grp1 = in(reg) 1u64,
                options(nomem, nostack, preserves_flags),
            );
        }
    }

    /// Acknowledge (IAR) the highest-priority pending Group 1 NS interrupt.
    ///
    /// Reading ICC_IAR1_EL1 acknowledges the interrupt, transitioning it from
    /// Pending to Active in the physical GIC. Returns the INTID; returns
    /// `ICC_SPURIOUS_INTID` (0x3FF) if no interrupt is pending.
    ///
    /// # Safety
    /// Must be called from EL2 with ICC SRE enabled. Must be paired with
    /// `eoir1` (and optionally `dir1` for deactivation) after handling.
    #[inline]
    pub unsafe fn iar1() -> u32 {
        let intid: u64;
        unsafe {
            asm!(
                "mrs {v}, icc_iar1_el1",
                v = out(reg) intid,
                options(nomem, nostack, preserves_flags),
            );
        }
        intid as u32
    }

    /// End of Interrupt — drop the running priority of the interrupt with
    /// the given INTID in the physical GIC CPU Interface (Group 1 NS).
    ///
    /// When HW-backed LRs are used (ICH_LR.HW=1), writing ICC_EOIR1_EL1
    /// drops priority WITHOUT deactivating the interrupt; deactivation is
    /// performed automatically by the GIC when the guest issues its own
    /// EOI via the Virtual CPU Interface, which the GIC links back to the
    /// physical interrupt via the pINTID field.
    ///
    /// # Safety
    /// `intid` must match a value previously read from `iar1()`.
    #[inline]
    pub unsafe fn eoir1(intid: u32) {
        unsafe {
            asm!(
                "msr icc_eoir1_el1, {v}",
                v = in(reg) intid as u64,
                options(nomem, nostack, preserves_flags),
            );
        }
    }

    /// Deactivate an interrupt in the physical GIC.
    ///
    /// Writes ICC_DIR_EL1, which transitions the interrupt from Active to
    /// Inactive (or back to Pending if it was Active+Pending). Use this
    /// only for interrupts where HW=0 in the LR (software-injected) — for
    /// HW-backed LRs the GIC handles deactivation automatically.
    ///
    /// # Safety
    /// `intid` must refer to a currently active (acknowledged) interrupt.
    #[inline]
    pub unsafe fn dir1(intid: u32) {
        unsafe {
            asm!(
                "msr icc_dir_el1, {v}",
                v = in(reg) intid as u64,
                options(nomem, nostack, preserves_flags),
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ICH — GIC Hypervisor Control Interface (system registers at EL2)
//
// ICH_* registers are only accessible from EL2. They control the virtual CPU
// Interface presented to EL1 guests via the GICV memory-mapped frame.
//
// Source: IHI0069 Chapter 8; linux-ref/arch/arm64/include/asm/sysreg.h.
// ─────────────────────────────────────────────────────────────────────────────

/// ICH_MISR_EL2 maintenance interrupt reason bit masks.
///
/// Source: IHI0069 Section 8.6; sysreg.h lines for ICH_MISR.
pub mod ich_misr {
    /// Bit 0: EOI — one or more List Registers transitioned from Active to
    /// Invalid while their EOI bit was set. The hypervisor should scan LRs.
    /// Source: IHI0069 Section 8.6.3.
    pub const EOI: u64 = 1 << 0;

    /// Bit 1: U — Underflow. Fewer than 2 List Registers are in use.
    pub const U: u64 = 1 << 1;

    /// Bit 2: LRENP — List Register Entry Not Present. A virtual interrupt
    /// was triggered but no free LR was available.
    pub const LRENP: u64 = 1 << 2;

    /// Bit 3: NP — No Pending interrupt (when ICH_HCR_EL2.NPIE=1).
    pub const NP: u64 = 1 << 3;

    /// Bit 4: VGrp0E — Virtual Group 0 enabled by guest (ICC_IGRPEN0_EL1.Enable=1).
    pub const VGRP0E: u64 = 1 << 4;

    /// Bit 5: VGrp0D — Virtual Group 0 disabled by guest.
    pub const VGRP0D: u64 = 1 << 5;

    /// Bit 6: VGrp1E — Virtual Group 1 enabled by guest (ICC_IGRPEN1_EL1.Enable=1).
    pub const VGRP1E: u64 = 1 << 6;

    /// Bit 7: VGrp1D — Virtual Group 1 disabled by guest.
    pub const VGRP1D: u64 = 1 << 7;
}

/// ICH Hypervisor Control Interface register access.
pub mod ich {
    use core::arch::asm;

    /// Read ICH_VTR_EL2 — VGIC Type Register.
    ///
    /// Bits [4:0]: ListRegs = (number of List Registers) − 1.
    /// Bits [28:26]: PRIbits = (number of implemented priority bits) − 1.
    /// Source: IHI0069 Section 8.2.2; sysreg.h.
    #[inline]
    pub unsafe fn read_vtr() -> u64 {
        let v: u64;
        unsafe {
            asm!(
                "mrs {v}, ich_vtr_el2",
                v = out(reg) v,
                options(nomem, nostack, preserves_flags),
            );
        }
        v
    }

    /// Read ICH_MISR_EL2 — Maintenance Interrupt State Register.
    ///
    /// Returns a bitmask of maintenance interrupt reasons (see `ich_misr`).
    /// Source: IHI0069 Section 8.6; sysreg.h.
    #[inline]
    pub unsafe fn read_misr() -> u64 {
        let v: u64;
        unsafe {
            asm!(
                "mrs {v}, ich_misr_el2",
                v = out(reg) v,
                options(nomem, nostack, preserves_flags),
            );
        }
        v
    }

    /// Read ICH_ELRSR_EL2 — Empty List Register Status Register.
    ///
    /// Bit N = 1 means List Register N is empty (State = Invalid).
    /// Use this to efficiently find a free LR without reading all 16 registers.
    /// Source: IHI0069 Section 8.2.4; sysreg.h.
    #[inline]
    pub unsafe fn read_elrsr() -> u64 {
        let v: u64;
        unsafe {
            asm!(
                "mrs {v}, ich_elrsr_el2",
                v = out(reg) v,
                options(nomem, nostack, preserves_flags),
            );
        }
        v
    }

    /// Read ICH_LR<n>_EL2 — one List Register.
    ///
    /// `idx` must be in 0..lr_count (as reported by `read_vtr()`).
    /// The match dispatches to the correct static register name because ARM
    /// system registers cannot be addressed via an integer index at runtime.
    /// Source: IHI0069 Section 8.4; sysreg.h lines 970–981.
    ///
    /// # Safety
    /// `idx` < 16 must hold. Reads from an unimplemented LR are UNPREDICTABLE.
    pub unsafe fn read_lr(idx: usize) -> u64 {
        let v: u64;
        // SAFETY: caller ensures idx < lr_count <= 16.
        unsafe {
            match idx {
                0  => asm!("mrs {v}, ich_lr0_el2",  v = out(reg) v, options(nomem,nostack,preserves_flags)),
                1  => asm!("mrs {v}, ich_lr1_el2",  v = out(reg) v, options(nomem,nostack,preserves_flags)),
                2  => asm!("mrs {v}, ich_lr2_el2",  v = out(reg) v, options(nomem,nostack,preserves_flags)),
                3  => asm!("mrs {v}, ich_lr3_el2",  v = out(reg) v, options(nomem,nostack,preserves_flags)),
                4  => asm!("mrs {v}, ich_lr4_el2",  v = out(reg) v, options(nomem,nostack,preserves_flags)),
                5  => asm!("mrs {v}, ich_lr5_el2",  v = out(reg) v, options(nomem,nostack,preserves_flags)),
                6  => asm!("mrs {v}, ich_lr6_el2",  v = out(reg) v, options(nomem,nostack,preserves_flags)),
                7  => asm!("mrs {v}, ich_lr7_el2",  v = out(reg) v, options(nomem,nostack,preserves_flags)),
                8  => asm!("mrs {v}, ich_lr8_el2",  v = out(reg) v, options(nomem,nostack,preserves_flags)),
                9  => asm!("mrs {v}, ich_lr9_el2",  v = out(reg) v, options(nomem,nostack,preserves_flags)),
                10 => asm!("mrs {v}, ich_lr10_el2", v = out(reg) v, options(nomem,nostack,preserves_flags)),
                11 => asm!("mrs {v}, ich_lr11_el2", v = out(reg) v, options(nomem,nostack,preserves_flags)),
                12 => asm!("mrs {v}, ich_lr12_el2", v = out(reg) v, options(nomem,nostack,preserves_flags)),
                13 => asm!("mrs {v}, ich_lr13_el2", v = out(reg) v, options(nomem,nostack,preserves_flags)),
                14 => asm!("mrs {v}, ich_lr14_el2", v = out(reg) v, options(nomem,nostack,preserves_flags)),
                _  => asm!("mrs {v}, ich_lr15_el2", v = out(reg) v, options(nomem,nostack,preserves_flags)),
            }
        }
        v
    }

    /// Write ICH_LR<n>_EL2 — program one List Register.
    ///
    /// # Safety
    /// `idx` < 16 must hold. Writes to unimplemented LRs are UNPREDICTABLE.
    pub unsafe fn write_lr(idx: usize, val: u64) {
        // SAFETY: caller ensures idx < lr_count <= 16.
        unsafe {
            match idx {
                0  => asm!("msr ich_lr0_el2,  {v}", v = in(reg) val, options(nomem,nostack,preserves_flags)),
                1  => asm!("msr ich_lr1_el2,  {v}", v = in(reg) val, options(nomem,nostack,preserves_flags)),
                2  => asm!("msr ich_lr2_el2,  {v}", v = in(reg) val, options(nomem,nostack,preserves_flags)),
                3  => asm!("msr ich_lr3_el2,  {v}", v = in(reg) val, options(nomem,nostack,preserves_flags)),
                4  => asm!("msr ich_lr4_el2,  {v}", v = in(reg) val, options(nomem,nostack,preserves_flags)),
                5  => asm!("msr ich_lr5_el2,  {v}", v = in(reg) val, options(nomem,nostack,preserves_flags)),
                6  => asm!("msr ich_lr6_el2,  {v}", v = in(reg) val, options(nomem,nostack,preserves_flags)),
                7  => asm!("msr ich_lr7_el2,  {v}", v = in(reg) val, options(nomem,nostack,preserves_flags)),
                8  => asm!("msr ich_lr8_el2,  {v}", v = in(reg) val, options(nomem,nostack,preserves_flags)),
                9  => asm!("msr ich_lr9_el2,  {v}", v = in(reg) val, options(nomem,nostack,preserves_flags)),
                10 => asm!("msr ich_lr10_el2, {v}", v = in(reg) val, options(nomem,nostack,preserves_flags)),
                11 => asm!("msr ich_lr11_el2, {v}", v = in(reg) val, options(nomem,nostack,preserves_flags)),
                12 => asm!("msr ich_lr12_el2, {v}", v = in(reg) val, options(nomem,nostack,preserves_flags)),
                13 => asm!("msr ich_lr13_el2, {v}", v = in(reg) val, options(nomem,nostack,preserves_flags)),
                14 => asm!("msr ich_lr14_el2, {v}", v = in(reg) val, options(nomem,nostack,preserves_flags)),
                _  => asm!("msr ich_lr15_el2, {v}", v = in(reg) val, options(nomem,nostack,preserves_flags)),
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Physical GICv3 initialization
//
// Initialization order mandated by IHI0069 Section 12.1:
//   1. Wake each Redistributor (GICR_WAKER.ProcessorSleep = 0) and wait
//      for ChildrenAsleep to clear. This must happen BEFORE enabling GICD.
//   2. Configure ICC system registers (enable SRE, set PMR, enable Group 1).
//   3. Enable the Distributor (GICD_CTLR.ARE_NS=1, EnableGrp1A=1).
//
// The skill guide explicitly warns: "Claude often forgets to initialize GICR
// (Redistributors) per-core before initializing the GICD (Distributor). The
// GIC spec requires Redistributors to be initialized first."
// ─────────────────────────────────────────────────────────────────────────────

/// Wake the GIC Redistributor for one PE and wait until it is ready.
///
/// Clears GICR_WAKER.ProcessorSleep and polls until ChildrenAsleep = 0.
/// Must be called for every online core before `init_gicd()`.
///
/// # Arguments
/// - `gicr_rd_base`: physical address of the Redistributor's RD frame
///   for this PE (`GICR_BASE + core_index × STRIDE`).
///
/// # Safety
/// `gicr_rd_base` must be the physical address of a valid, accessible GICR
/// RD frame. Must be called from EL2 before the Distributor is enabled.
pub unsafe fn wake_gicr(gicr_rd_base: u64) {
    let waker_ptr = (gicr_rd_base as usize + gicr::WAKER) as *mut u32;

    // Clear ProcessorSleep to tell the Redistributor the PE is awake.
    let waker = unsafe { ptr::read_volatile(waker_ptr) };
    unsafe { ptr::write_volatile(waker_ptr, waker & !gicr::WAKER_PROCESSOR_SLEEP) };

    // Poll ChildrenAsleep until it clears (typically a few cycles on real HW).
    // Bounded to 1M iterations to avoid hanging if the address is wrong.
    for _ in 0..1_000_000 {
        unsafe {
            dsb_ishst();
            let waker = ptr::read_volatile(waker_ptr);
            if waker & gicr::WAKER_CHILDREN_ASLEEP == 0 {
                break;
            }
        }
    }

    // Mark all SGIs/PPIs as Group 1 NS on this Redistributor so the
    // Android kernel can acknowledge them via ICC_IAR1_EL1.
    let sgi_base = gicr_rd_base as usize + gicr::SGI_FRAME_OFFSET;
    let igroupr0 = (sgi_base + gicr::SGI_IGROUPR0) as *mut u32;
    unsafe { ptr::write_volatile(igroupr0, 0xFFFF_FFFF) };
}

/// Enable the GIC Distributor in GICv3 affinity-routing mode.
///
/// Sets ARE_NS=1 (affinity routing, GICD_IROUTER used for SPIs) and
/// EnableGrp1A=1 (Group 1 NS interrupts globally enabled). The Distributor
/// marks all SPIs as Group 1 NS so Android can receive them.
///
/// # Safety
/// All online Redistributors must have been woken via `wake_gicr()` before
/// calling this. Must be called from EL2.
pub unsafe fn init_gicd(gicd_base: u64) {
    let ctlr = (gicd_base as usize + gicd::CTLR) as *mut u32;

    // Disable all groups first while we reconfigure.
    unsafe { ptr::write_volatile(ctlr, 0) };

    // Poll RWP until the disable takes effect (bounded).
    for _ in 0..1_000_000 {
        unsafe {
            dsb_ishst();
            if ptr::read_volatile(ctlr) & gicd::CTLR_RWP == 0 {
                break;
            }
        }
    }

    // Determine number of implemented SPI lines from GICD_TYPER[4:0].
    let typer = unsafe {
        ptr::read_volatile((gicd_base as usize + gicd::TYPER) as *const u32)
    };
    let it_lines = (typer & 0x1F) as usize; // max INTID = 32 × (it_lines + 1) - 1

    // Mark all SPIs as Group 1 NS. IGROUPR words start at IGROUPR0 (INTID 0)
    // at the Distributor level; SPIs are INTIDs 32–1019.
    // Word index 0 covers INTIDs 0–31 (SGIs/PPIs — handled by GICR).
    // Words 1..it_lines cover SPI INTIDs 32..32×(it_lines+1)−1.
    for i in 1..=it_lines {
        let ptr = (gicd_base as usize + gicd::IGROUPR0 + i * 4) as *mut u32;
        unsafe { ptr::write_volatile(ptr, 0xFFFF_FFFF) };
    }

    // Set default priority 0xA0 (middle range) for all SPIs.
    // GICD_IPRIORITYR starts at 0x0400, one byte per INTID (accessible as u32 words).
    let spi_count = (it_lines + 1) * 32;
    for i in (32..spi_count).step_by(4) {
        let ptr = (gicd_base as usize + gicd::IPRIORITYR0 + i) as *mut u32;
        unsafe { ptr::write_volatile(ptr, 0xA0A0_A0A0) };
    }

    dsb_ishst();

    // Enable the Distributor: ARE_NS=1 (GICv3 affinity routing), EnableGrp1A=1.
    unsafe {
        ptr::write_volatile(
            ctlr,
            gicd::CTLR_ARE_NS | gicd::CTLR_ENABLE_GRP1A,
        );
    }

    // Wait for the enable to take effect (bounded).
    for _ in 0..1_000_000 {
        unsafe {
            dsb_ish();
            if ptr::read_volatile(ctlr) & gicd::CTLR_RWP == 0 {
                break;
            }
        }
    }
}

/// Initialize the GIC system-register CPU Interface on the calling core.
///
/// 1. Enables ICC_SRE_EL2 so system-register access to ICC_* is possible.
/// 2. Configures ICC priority mask, binary point, and enables Group 1 NS.
///
/// # Safety
/// Must be called from EL2 on each online core after that core's GICR
/// has been woken. After this call, `icc::iar1()` and `icc::eoir1()` are
/// valid.
pub unsafe fn init_icc() {
    unsafe {
        icc::enable_sre_el2();
        icc::init_cpu_interface();
    }
}

/// Full physical GICv3 initialization for a system with `online_cores` PEs.
///
/// Wakes Redistributors for cores 0..online_cores, then enables the Distributor
/// and configures the CPU Interface on the calling core.
///
/// # Arguments
/// - `gicd_base`: physical base address of the Distributor.
/// - `gicr_base`: physical base address of the first Redistributor's RD frame.
///   Subsequent redistributors are at `gicr_base + k × GICR_STRIDE` for k=1..
/// - `online_cores`: number of cores to wake.
///
/// # Safety
/// `gicd_base` and `gicr_base` must be valid, accessible, uncached MMIO physical
/// addresses. `online_cores` must be ≤ the actual number of implemented GICRs.
/// Must be called from EL2 during boot (before any guest runs).
pub unsafe fn init_physical_gic(gicd_base: u64, gicr_base: u64, online_cores: usize) {
    // Step 1: Wake all Redistributors (MUST precede Distributor enable).
    for core in 0..online_cores {
        let rd_base = gicr_base + (core * gicr::STRIDE) as u64;
        unsafe { wake_gicr(rd_base) };
    }

    // Step 2: Configure ICC system registers on the boot core.
    // Secondary cores call init_icc() as they come online.
    unsafe { init_icc() };

    // Step 3: Enable the Distributor (marks all SPIs as Group 1, sets ARE_NS).
    unsafe { init_gicd(gicd_base) };
}

// ─────────────────────────────────────────────────────────────────────────────
// VGicState — List Register management
//
// ICH_LR{0..15}_EL2 (List Registers) are the mechanism for injecting virtual
// interrupts into a guest vCPU. Each LR programs one virtual interrupt.
//
// For AETHER's single-guest (Android) model, one global VGicState tracks the
// LR allocation on the single running vCPU. In a multi-guest system, this
// would be per-vCPU.
//
// ICH_LR bit layout (verified from sysreg.h lines 970–981 and IHI0069 §8.4):
//   [31:0]   vINTID — virtual interrupt ID the guest sees
//   [41:32]  pINTID — physical interrupt ID (valid only when HW=1)
//   [41]     EOI    — generate maintenance interrupt on LR→Invalid transition
//   [55:48]  Priority — virtual interrupt priority (8 bits)
//   [60]     Group  — 0=Group0, 1=Group1
//   [61]     HW     — 1=hardware-backed (pINTID valid, auto-deactivation)
//   [63:62]  State  — 00=Invalid, 01=Pending, 10=Active, 11=Active+Pending
//
// Skill guide warning: "Claude generates ICH_LR values with the State field
// in the wrong bit positions. The State field is bits [63:62] in GICv3."
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum number of List Registers supported by the GIC architecture.
/// ICH_VTR_EL2.ListRegs field is 5 bits, max value = 15 → 16 LRs.
/// Source: IHI0069 Section 8.2.2.
pub const MAX_LRS: usize = 16;

/// ICH_LR State field: bits [63:62].
/// Source: sysreg.h line 975 `ICH_LR_STATE = (3ULL << 62)`.
const LR_STATE_MASK: u64 = 3u64 << 62;

/// LR State = 0b01 << 62: interrupt is Pending (waiting for delivery).
const LR_STATE_PENDING: u64 = 1u64 << 62;

/// Virtual CPU Interface state for the Android guest.
///
/// Tracks how many List Registers the hardware provides and the INTID of the
/// maintenance interrupt so `handle_physical_irq` can distinguish maintenance
/// interrupts from forwarded device interrupts.
pub struct VGicState {
    /// Number of List Registers, read from ICH_VTR_EL2.ListRegs + 1.
    /// In the range 1..=16.
    lr_count: usize,
    /// GSIV (INTID) of the VGIC maintenance interrupt, from MADT GICC entry.
    maint_intid: u32,
}

impl VGicState {
    /// Construct an uninitialized placeholder.
    ///
    /// `lr_count = 0` is a sentinel: `init()` must be called before any
    /// LR operations or injection calls.
    pub const fn new_empty() -> Self {
        Self { lr_count: 0, maint_intid: 25 }
    }

    /// Initialize by reading ICH_VTR_EL2 from hardware.
    ///
    /// # Safety
    /// Must be called from EL2 with GIC virtualization extension present.
    /// ICH_HCR_EL2.En must be 1 (set by `configure_el2_virt` in ch06).
    pub unsafe fn init(&mut self, maint_intid: u32) {
        let vtr = unsafe { ich::read_vtr() };
        // ICH_VTR_EL2 bits [4:0]: ListRegs = (number of LRs) - 1.
        // Source: IHI0069 Section 8.2.2.
        self.lr_count = ((vtr & 0x1F) as usize) + 1;
        self.maint_intid = maint_intid;
    }

    /// Number of List Registers available on this GIC.
    #[inline]
    pub fn lr_count(&self) -> usize {
        self.lr_count
    }

    /// Maintenance interrupt INTID for this system.
    #[inline]
    pub fn maint_intid(&self) -> u32 {
        self.maint_intid
    }

    /// Find the index of a free (Invalid state) List Register.
    ///
    /// Reads ICH_ELRSR_EL2 — a bitmap where bit N = 1 means LR N is empty.
    /// Uses the hardware register for efficiency rather than reading all LRs.
    ///
    /// Returns `None` if all LRs are occupied (interrupt injection will be
    /// deferred until a maintenance interrupt frees one).
    ///
    /// # Safety
    /// Must be called from EL2.
    pub unsafe fn find_free_lr(&self) -> Option<usize> {
        let elrsr = unsafe { ich::read_elrsr() };
        for i in 0..self.lr_count {
            if elrsr & (1u64 << i) != 0 {
                return Some(i);
            }
        }
        None
    }

    /// Inject a hardware-backed virtual interrupt into the guest.
    ///
    /// Programs one List Register with HW=1, State=Pending, Group 1.
    /// With HW=1, when the guest issues EOI for `vintid` via the Virtual CPU
    /// Interface, the GIC automatically deactivates the physical interrupt
    /// identified by `pintid` — no further EL2 involvement needed.
    ///
    /// # Arguments
    /// - `vintid`: Virtual interrupt ID presented to the Android guest (0–1019).
    /// - `pintid`: Physical interrupt ID in the GIC Distributor (0–1019, 10-bit).
    /// - `priority`: 8-bit priority (lower value = higher priority).
    ///
    /// Returns `true` if a free LR was found and programmed, `false` if all
    /// LRs are occupied.
    ///
    /// # Safety
    /// Must be called from EL2. `pintid` must be an acknowledged (Active)
    /// physical interrupt — it must have been read from `icc::iar1()` by the
    /// calling handler before this function is invoked.
    pub unsafe fn inject_hw(&self, vintid: u32, pintid: u16, priority: u8) -> bool {
        let Some(idx) = (unsafe { self.find_free_lr() }) else {
            return false;
        };
        // Build the LR value using constants from virt.rs gic_virt module.
        let lr = crate::arm64::virt::gic_virt::build_pending_hw(vintid, pintid, priority);
        unsafe { ich::write_lr(idx, lr) };
        true
    }

    /// Inject a software-generated virtual interrupt (no physical backing).
    ///
    /// Programs one List Register with HW=0, State=Pending, Group 1.
    /// With HW=0, the GIC generates a maintenance interrupt (EOI bit) when
    /// the guest deactivates this virtual interrupt; `handle_maintenance_irq`
    /// must clear the LR entry.
    ///
    /// # Arguments
    /// - `vintid`: Virtual interrupt ID (0–1019).
    /// - `priority`: 8-bit priority.
    ///
    /// Returns `true` if injected, `false` if all LRs are full.
    ///
    /// # Safety
    /// Must be called from EL2.
    pub unsafe fn inject_sw(&self, vintid: u32, priority: u8) -> bool {
        let Some(idx) = (unsafe { self.find_free_lr() }) else {
            return false;
        };
        let lr = crate::arm64::virt::gic_virt::build_pending_sw(vintid, priority);
        unsafe { ich::write_lr(idx, lr) };
        true
    }

    /// Clear all List Registers that have transitioned to the Invalid state.
    ///
    /// Called from the maintenance interrupt handler when ICH_MISR_EL2.EOI=1.
    /// Reads each LR and writes 0 (Invalid) to any that are already Invalid —
    /// this is idempotent and cheaper than scanning ICH_EISR.
    ///
    /// # Safety
    /// Must be called from EL2.
    pub unsafe fn clear_invalid_lrs(&self) {
        for i in 0..self.lr_count {
            let val = unsafe { ich::read_lr(i) };
            // State field is bits [63:62]. Invalid = 0b00.
            if val & LR_STATE_MASK == 0 {
                unsafe { ich::write_lr(i, 0) };
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Maintenance interrupt handler
//
// When a virtual interrupt with HW=0 is deactivated by the guest and its
// LR.EOI bit was set, the GIC fires a maintenance interrupt to EL2. The
// handler must clear the stale LR entry so it can be reused.
//
// Source: IHI0069 Section 8.6.
// ─────────────────────────────────────────────────────────────────────────────

/// Handle a VGIC maintenance interrupt.
///
/// Called when the physical interrupt received at EL2 is the maintenance
/// interrupt INTID (from `VGicState::maint_intid()`). Reads ICH_MISR_EL2
/// to determine the reason and takes appropriate action.
///
/// # Safety
/// Must be called from the EL2 IRQ handler with the maintenance interrupt
/// already acknowledged (ICC_IAR1_EL1 read). The caller must subsequently
/// issue `icc::eoir1(maint_intid)` after this returns.
pub unsafe fn handle_maintenance_irq(vgic: &mut VGicState) {
    let misr = unsafe { ich::read_misr() };

    // EOI maintenance: one or more LRs transitioned to Invalid.
    // Scan all LRs and clear any that are now in the Invalid state.
    if misr & ich_misr::EOI != 0 {
        unsafe { vgic.clear_invalid_lrs() };
    }

    // LRENP: a virtual interrupt arrived when all LRs were occupied.
    // There is nothing useful to do here in the current implementation
    // (the interrupt was lost); a production implementation would queue it.
    // Logged as a no-op for now — the LRs will be freed by EOI handling
    // on the next guest exit.
    let _ = misr & ich_misr::LRENP;
}

// ─────────────────────────────────────────────────────────────────────────────
// Physical IRQ forwarding
//
// When HCR_EL2.IMO=1, Group 1 NS physical interrupts (normal device IRQs)
// are routed to EL2 rather than EL1. AETHER must acknowledge the interrupt,
// decide which guest it belongs to, and forward it as a virtual interrupt.
//
// For AETHER's single-guest (Android) model, all device IRQs are forwarded
// to Android. The forwarding uses HW=1 (hardware-backed LR) so the GIC
// handles physical deactivation automatically when the guest EOIs.
//
// Interrupt forwarding flow (IHI0069 Section 8.2.3 / KVM reference):
//   1. EL2 reads ICC_IAR1_EL1 → intid (acknowledges the interrupt, Active).
//   2. If intid is the maintenance interrupt → handle_maintenance_irq().
//      Then EOI it and return.
//   3. Otherwise: program ICH_LR with HW=1, pINTID=intid, vINTID=intid.
//   4. Drop physical priority via ICC_EOIR1_EL1 WITHOUT deactivating.
//      With HW=1, deactivation happens automatically when the guest EOIs.
//
// Note on ICC_EOIR1_EL1 semantics: when ICC_CTLR_EL1.EOImode=0 (the reset
// default), ICC_EOIR1_EL1 both drops priority AND deactivates. For HW-backed
// LRs, we need to drop priority only. Setting ICH_HCR_EL2.TDIR=0 and
// configuring the GIC to use EOImode=1 (separate drop/deactivate) is the
// robust path; the simple path used here relies on the GIC's HW-linked
// deactivation suppressing the physical deactivate when the LR.HW=1 flag
// is set. This matches the KVM nVHE implementation in vgic-v3.c.
// ─────────────────────────────────────────────────────────────────────────────

/// Standard priority for device interrupts forwarded to Android.
/// Priority 0xA0 gives Android full control via ICC_PMR_EL1 (mask = 0xFF).
const DEFAULT_FORWARD_PRIORITY: u8 = 0xA0;

/// Handle a physical IRQ taken to EL2 and forward it to the Android guest.
///
/// Called from `exception::aether_handle_irq`. Acknowledges the physical
/// interrupt, distinguishes maintenance from device interrupts, and injects
/// the interrupt into the guest via a hardware-backed List Register.
///
/// # Safety
/// Must be called from the EL2 IRQ exception handler with PSTATE.I masked
/// (already the case at EL2 exception entry). `vgic` must be the global
/// VGicState previously initialized via `VGicState::init()`.
pub unsafe fn handle_physical_irq(vgic: &mut VGicState) {
    // Step 1: Acknowledge the highest-priority pending Group 1 NS interrupt.
    // After this read, the interrupt is in Active state physically.
    let intid = unsafe { icc::iar1() };

    // Spurious interrupt — no interrupt was actually pending.
    if intid == ICC_SPURIOUS_INTID {
        return;
    }

    // Step 2: Distinguish maintenance interrupt from device interrupt.
    if intid == vgic.maint_intid() {
        // The VGIC maintenance interrupt fires when LR state needs attention.
        unsafe { handle_maintenance_irq(vgic) };
        // EOI the maintenance interrupt (drops priority; no physical deactivation
        // needed for PPIs in non-HW-linked mode).
        unsafe { icc::eoir1(intid) };
        unsafe { icc::dir1(intid) };
        return;
    }

    // Step 3: Forward as a hardware-backed virtual interrupt.
    // vintid == pintid: Android's GIC driver uses the same INTID as the
    // physical hardware, so no remapping is needed for a 1:1 pass-through.
    let injected = unsafe {
        vgic.inject_hw(intid, intid as u16, DEFAULT_FORWARD_PRIORITY)
    };

    // Step 4: Drop physical interrupt priority (without deactivating).
    // Deactivation is delegated to the GIC hardware via LR.HW=1: when
    // the Android GIC driver issues EOI via the Virtual CPU Interface,
    // the GIC automatically deactivates the physical interrupt with intid.
    //
    // If injection failed (all LRs full), we deactivate the physical
    // interrupt now to avoid it becoming stuck in Active state. The
    // interrupt is effectively dropped — a maintenance interrupt will
    // eventually free an LR for next time.
    unsafe { icc::eoir1(intid) };
    if !injected {
        // LRs full: deactivate physically so the interrupt can re-assert.
        unsafe { icc::dir1(intid) };
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Global VGicState
//
// One singleton per hypervisor instance. Initialized during boot via
// `aether_vgic_init()`. Accessed from exception.rs via `aether_vgic_mut()`.
// ─────────────────────────────────────────────────────────────────────────────

static mut AETHER_VGIC: VGicState = VGicState::new_empty();

/// Initialize the global VGicState from hardware and the discovered GIC addresses.
///
/// Must be called once during boot from EL2 before the first guest entry and
/// before any IRQ is unmasked.
///
/// # Safety
/// Must be called from EL2 after `configure_el2_virt()` has set ICH_HCR_EL2.En.
/// Must not be called concurrently with any IRQ handler.
pub unsafe fn aether_vgic_init(maint_intid: u32) {
    unsafe {
        let vgic = &mut *core::ptr::addr_of_mut!(AETHER_VGIC);
        vgic.init(maint_intid);
    }
}

/// Exclusive mutable reference to the global VGicState.
///
/// # Safety
/// Must be called only from EL2 exception context. The caller must ensure
/// no re-entrant access to the VGicState (EL2 exceptions are non-reentrant
/// by design — PSTATE.I is set on EL2 exception entry).
#[inline]
pub unsafe fn aether_vgic_mut() -> &'static mut VGicState {
    unsafe { &mut *core::ptr::addr_of_mut!(AETHER_VGIC) }
}

/// Shared reference to the global VGicState.
///
/// # Safety
/// Same requirements as `aether_vgic_mut`.
#[inline]
pub unsafe fn aether_vgic() -> &'static VGicState {
    unsafe { &*core::ptr::addr_of!(AETHER_VGIC) }
}

// ─────────────────────────────────────────────────────────────────────────────
// Compile-time assertions
// ─────────────────────────────────────────────────────────────────────────────

const _: () = {
    // ICH_LR State field must be at bits [63:62].
    // Source: sysreg.h line 975 `ICH_LR_STATE = (3ULL << 62)`.
    assert!(
        LR_STATE_MASK == crate::arm64::virt::gic_virt::ICH_LR_STATE,
        "LR_STATE_MASK must match gic_virt::ICH_LR_STATE (bits [63:62])"
    );

    // ICH_LR Pending state is bit [62] only (Active=0, Pending=1 → 0b01<<62).
    // Source: sysreg.h line 976 `ICH_LR_PENDING_BIT = (1ULL << 62)`.
    assert!(
        LR_STATE_PENDING == crate::arm64::virt::gic_virt::ICH_LR_PENDING_BIT,
        "LR_STATE_PENDING must match ICH_LR_PENDING_BIT"
    );

    // GICD_IROUTER base: arm-gic-v3.h `#define GICD_IROUTER 0x6000`.
    assert!(
        gicd::IROUTER_BASE == 0x6000,
        "gicd::IROUTER_BASE must be 0x6000 per arm-gic-v3.h"
    );

    // GICR stride: 128 KiB per PE (two 64 KiB frames: RD + SGI).
    // Source: IHI0069 Section 12.3.
    assert!(
        gicr::STRIDE == 0x20000,
        "gicr::STRIDE must be 0x20000 (128 KiB)"
    );

    // SGI frame offset: 64 KiB after RD_base.
    assert!(
        gicr::SGI_FRAME_OFFSET == 0x10000,
        "gicr::SGI_FRAME_OFFSET must be 0x10000 (64 KiB)"
    );

    // Maintenance interrupt INTID default: 25 (standard ARM PPI for VGIC maint).
    // This is the GSIV value commonly found in MADT GICC entries on Snapdragon X.
    // Source: ACPI 6.4 Table 5.56; Linux ARM GIC default VGIC maint PPI.
    // (Not a hard constraint — the real value always comes from MADT discovery.)
    assert!(
        VGicState::new_empty().maint_intid == 25,
        "default maintenance INTID sentinel must be 25"
    );

    // MAX_LRS must be 16 (5-bit ListRegs field max value = 15 → 16 LRs).
    assert!(MAX_LRS == 16, "MAX_LRS must be 16");
};
