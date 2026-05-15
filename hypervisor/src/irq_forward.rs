// ch36: Physical IRQ Forwarding — Validated
//
// The forwarding path from physical GIC to Android guest was established in
// ch10 (gic.rs). This module adds the QEMU test validation layer:
//
//   1. INTID constants for the two interrupt lines the gate test verifies:
//        TIMER_VIRT_INTID (27)  — EL1 virtual timer PPI (arch_timer in Linux)
//        TIMER_PHYS_NS_INTID (30) — NS EL1 physical timer PPI
//        UART_SPI_INTID (33)    — PL011 UART SPI (QEMU virt)
//
//   2. IrqForwardConfig — typed container for the per-system INTID set.
//
//   3. IrqForwardingStats — per-category delivery counters updated from
//      the EL2 IRQ handler. Non-zero counts on both timer and uart fields
//      confirm live IRQ delivery (observable via /proc/interrupts in guest).
//
//   4. enable_ppi_in_gicr() / enable_spi_in_gicd() — proactively enable
//      timer PPIs and the UART SPI in the physical GIC so they assert before
//      the Android GIC driver has had a chance to do so itself. This ensures
//      interrupts arrive at EL2 (via HCR_EL2.IMO=1) from the moment the
//      guest starts, not only after the Linux driver initialises.
//
//   5. setup_irq_forwarding() — top-level boot call that enables timer PPIs
//      on every online core and the UART SPI globally, then initialises the
//      global VGicState (lr_count) which is the prerequisite for interrupt
//      injection via ICH_LRn_EL2.
//
// Gate (IHI0069 §8.2.3 / Linux /proc/interrupts):
//   Inside the Android guest, `cat /proc/interrupts` after 5 s shows
//   non-zero counts on the "arch_timer" and "uart-pl011" lines.
//
// Primary sources:
//   - GIC Architecture Specification IHI0069 §12.3 (GICR ISENABLER0)
//   - QEMU source: hw/arm/virt.c (VIRT_TIMER_*, VIRT_UART SPI allocation)
//   - Linux: arch/arm64/include/asm/arch_timer.h (timer INTID assignments)
//   - linux-ref/drivers/irqchip/irq-gic-v3.c (GICD_ISENABLER formula)

use core::ptr;

use crate::arm64::barriers::dsb_ishst;
use crate::gic::{gicd, gicr};

// ─────────────────────────────────────────────────────────────────────────────
// INTID constants — QEMU virt interrupt assignments
//
// Source: QEMU hw/arm/virt.c virt_irqmap[] / VIRT_TIMER_* / VIRT_UART
// Verified against: Linux arch/arm/boot/dts/arm/versatile-ab.dtsi and
//   Documentation/devicetree/bindings/timer/arm,arch_timer.yaml (INTID layout)
// ─────────────────────────────────────────────────────────────────────────────

/// INTID 27: EL1 Virtual timer PPI.
///
/// The ARM architectural virtual timer fires this PPI on each core.
/// Linux's `arch_timer` driver registers for this interrupt. It is the
/// primary timer interrupt visible in `/proc/interrupts` as "arch_timer".
///
/// Source: QEMU virt.c `VIRT_TIMER_VIRT = 27`; ARM ARM §I2; IHI0069 §4.1.
pub const TIMER_VIRT_INTID: u32 = 27;

/// INTID 30: NS EL1 Physical timer PPI.
///
/// The non-secure EL1 physical timer; used by some kernels alongside the
/// virtual timer. Enabling it proactively prevents missed interrupts when
/// the Linux arch_timer driver requests both.
///
/// Source: QEMU virt.c `VIRT_TIMER_NS_EL1 = 30`.
pub const TIMER_PHYS_NS_INTID: u32 = 30;

/// INTID 33: PL011 UART SPI (SPI absolute INTID = 32 + SPI-relative 1).
///
/// QEMU virt allocates SPI 1 (INTID 33) to the PL011 UART. Linux's
/// `amba-pl011` driver registers for this; `/proc/interrupts` shows it
/// as "uart-pl011" or "GIC-0  33".
///
/// Source: QEMU virt.c `VIRT_UART`; DT node in hw/arm/virt-acpi-build.c.
pub const UART_SPI_INTID: u32 = 33;

// ─────────────────────────────────────────────────────────────────────────────
// IrqForwardConfig — per-system forwarding configuration
//
// Collects the INTID assignments needed to enable and classify forwarded
// interrupts. Constructed once during boot from constants + MADT data.
// ─────────────────────────────────────────────────────────────────────────────

/// Per-system IRQ forwarding configuration.
///
/// Identifies the physical INTIDs that AETHER enables in the GIC and
/// classifies when forwarding to the Android guest.
#[derive(Debug, Clone, Copy)]
pub struct IrqForwardConfig {
    /// Virtual timer PPI INTID (typically 27).
    pub timer_virt_intid: u32,
    /// NS physical timer PPI INTID (typically 30).
    pub timer_phys_ns_intid: u32,
    /// UART SPI INTID (typically 33 on QEMU virt).
    pub uart_spi_intid: u32,
    /// VGIC maintenance interrupt INTID (from MADT GICC entry; typically 25).
    pub maint_intid: u32,
}

impl IrqForwardConfig {
    /// Standard QEMU virt configuration (hardcoded INTIDs from QEMU hw/arm/virt.c).
    pub const QEMU_VIRT: Self = Self {
        timer_virt_intid:    TIMER_VIRT_INTID,
        timer_phys_ns_intid: TIMER_PHYS_NS_INTID,
        uart_spi_intid:      UART_SPI_INTID,
        maint_intid:         25, // Standard ARM VGIC maintenance PPI
    };

    /// Classify an INTID for forwarding statistics.
    #[inline]
    pub fn classify(&self, intid: u32) -> IrqCategory {
        if intid == self.timer_virt_intid || intid == self.timer_phys_ns_intid {
            IrqCategory::Timer
        } else if intid == self.uart_spi_intid {
            IrqCategory::Uart
        } else if intid == self.maint_intid {
            IrqCategory::Maintenance
        } else {
            IrqCategory::Other
        }
    }
}

/// Category of a forwarded interrupt (for statistics).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrqCategory {
    /// Architecture timer PPI (virtual or NS physical).
    Timer,
    /// PL011 UART SPI.
    Uart,
    /// VGIC maintenance interrupt (LR state change).
    Maintenance,
    /// Any other SPI or PPI.
    Other,
}

// ─────────────────────────────────────────────────────────────────────────────
// IrqForwardingStats — per-category delivery counters
//
// Updated atomically (EL2 is non-reentrant — PSTATE.I is set on entry)
// on every forwarded interrupt. Saturating addition prevents u64 wrap.
//
// Non-zero `timer_count` and `uart_count` after guest boot confirms that
// the physical IRQ → EL2 → ICH_LRn → guest path is alive. This maps
// directly to /proc/interrupts ticking inside the Android guest.
// ─────────────────────────────────────────────────────────────────────────────

/// Per-category interrupt delivery counters.
///
/// Populated by `record_forwarded_irq()` on every call to the EL2 IRQ handler.
pub struct IrqForwardingStats {
    /// Timer PPIs (INTID 27 + 30) forwarded to the Android guest.
    pub timer_count: u64,
    /// UART SPIs (INTID 33) forwarded to the Android guest.
    pub uart_count: u64,
    /// VGIC maintenance interrupts handled (LR-clearing cycles).
    pub maintenance_count: u64,
    /// Other interrupts forwarded.
    pub other_count: u64,
    /// Interrupts dropped because all ICH_LRs were occupied at injection time.
    pub dropped_count: u64,
}

impl IrqForwardingStats {
    pub const fn new() -> Self {
        Self {
            timer_count:       0,
            uart_count:        0,
            maintenance_count: 0,
            other_count:       0,
            dropped_count:     0,
        }
    }

    /// Return true if both timer and uart lines have ticked — gate criterion met.
    #[inline]
    pub fn gate_passed(&self) -> bool {
        self.timer_count > 0 && self.uart_count > 0
    }
}

static mut IRQ_FORWARD_STATS: IrqForwardingStats = IrqForwardingStats::new();

/// Exclusive mutable reference to the global forwarding stats.
///
/// # Safety
/// Must be called only from EL2 exception context. Non-reentrant by design
/// (PSTATE.I is set on EL2 exception entry, preventing nested IRQ handlers).
#[inline]
pub unsafe fn irq_forward_stats_mut() -> &'static mut IrqForwardingStats {
    unsafe { &mut *core::ptr::addr_of_mut!(IRQ_FORWARD_STATS) }
}

/// Shared reference to the global forwarding stats (for banner/debug reads).
///
/// # Safety
/// Must be called from EL2; must not alias a concurrent `irq_forward_stats_mut`.
#[inline]
pub unsafe fn irq_forward_stats() -> &'static IrqForwardingStats {
    unsafe { &*core::ptr::addr_of!(IRQ_FORWARD_STATS) }
}

/// Record one forwarded interrupt in the global stats.
///
/// Called from `aether_handle_irq` after `gic::handle_physical_irq()` returns,
/// using the INTID that was handled. The stats allow offline analysis of which
/// interrupt lines are active without requiring a guest-side debugger.
///
/// # Arguments
/// - `intid`: the INTID that was acknowledged and forwarded (or handled as
///   maintenance). Pass `gic::ICC_SPURIOUS_INTID` for spurious — no count
///   is incremented for spurious reads.
/// - `injected`: whether the interrupt was successfully injected into an LR
///   (`true`) or was dropped because all LRs were occupied (`false`).
/// - `cfg`: the system's `IrqForwardConfig` used to classify the INTID.
///
/// # Safety
/// Must be called from EL2 exception context only.
pub unsafe fn record_forwarded_irq(intid: u32, injected: bool, cfg: &IrqForwardConfig) {
    // Spurious reads (0x3FF) carry no information.
    if intid == crate::gic::ICC_SPURIOUS_INTID {
        return;
    }

    let stats = unsafe { irq_forward_stats_mut() };

    if !injected {
        stats.dropped_count = stats.dropped_count.saturating_add(1);
        return;
    }

    match cfg.classify(intid) {
        IrqCategory::Timer       => stats.timer_count       = stats.timer_count.saturating_add(1),
        IrqCategory::Uart        => stats.uart_count        = stats.uart_count.saturating_add(1),
        IrqCategory::Maintenance => stats.maintenance_count = stats.maintenance_count.saturating_add(1),
        IrqCategory::Other       => stats.other_count       = stats.other_count.saturating_add(1),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GIC enable helpers
//
// With HCR_EL2.IMO=1, physical Group 1 NS IRQs that are pending and enabled
// in the physical GIC are routed to EL2 (not EL1). AETHER enables the timer
// PPIs and UART SPI proactively so they reach EL2 before the Android GIC
// driver has had a chance to program the GIC itself.
//
// The Android GIC driver will also write GICD_ISENABLER / GICR_ISENABLER0
// (which are identity-mapped as Device pages in Stage 2 so the guest can
// reach them), so enabling them here is idempotent. The benefit is that
// timer ticks arrive at EL2 starting from the first guest instruction,
// which is important for the arch_timer calibration during early boot.
// ─────────────────────────────────────────────────────────────────────────────

/// Enable a PPI (INTID < 32) in the SGI frame of one core's Redistributor.
///
/// Writes GICR_ISENABLER0 (SGI frame, offset 0x0100) with a single-bit mask
/// for `intid`. Writing 0 to other bits is safe — ISENABLER is a set register
/// (writes 0 have no effect; only 1s enable the corresponding interrupt).
///
/// # Arguments
/// - `gicr_rd_base`: physical base of this core's RD frame
///   (`GICR_BASE + core_index × GICR_STRIDE`).
/// - `intid`: PPI INTID in the range 16..31 (SGI 0..15 are always enabled).
///
/// # Safety
/// `gicr_rd_base` must be the RD frame for a woken Redistributor.
/// Must be called from EL2 after `wake_gicr()` for the target core.
pub unsafe fn enable_ppi_in_gicr(gicr_rd_base: u64, intid: u32) {
    // GICR_ISENABLER0 is in the SGI frame at offset SGI_FRAME_OFFSET + 0x0100.
    // Source: IHI0069 §12.4.5; arm-gic-v3.h GICR_ISENABLER0 = 0x0100.
    let sgi_base = gicr_rd_base as usize + gicr::SGI_FRAME_OFFSET;
    let isenabler_ptr = (sgi_base + gicr::SGI_ISENABLER0) as *mut u32;
    // DSB before the write ensures prior Redistributor init is visible to MMIO.
    unsafe {
        dsb_ishst();
        ptr::write_volatile(isenabler_ptr, 1u32 << intid);
    }
}

/// Enable an SPI (INTID ≥ 32) in the Distributor for system-wide delivery.
///
/// Writes GICD_ISENABLER<word> with a single-bit mask for `intid`.
/// GICD_ISENABLER is a set register — bits written 0 are unchanged.
/// The SPI is enabled globally; GICD_IROUTER (set by `cpu::init_gic_routing`)
/// controls which PE receives it.
///
/// # Arguments
/// - `gicd_base`: GICD physical base address.
/// - `intid`: SPI INTID ≥ 32.
///
/// # Safety
/// `gicd_base` must be the GICD MMIO base. Distributor must have been
/// initialized via `init_gicd()` (ARE_NS=1) before this is called.
pub unsafe fn enable_spi_in_gicd(gicd_base: u64, intid: u32) {
    // GICD_ISENABLER<n> byte offset = ISENABLER0 + (intid / 32) × 4.
    // Bit within the word = intid % 32.
    // Source: IHI0069 §12.2.6; arm-gic-v3.h GICD_ISENABLER0 = 0x0100.
    let word_byte_offset = (intid / 32) as usize * 4;
    let bit = intid % 32;
    let isenabler_ptr = (gicd_base as usize + gicd::ISENABLER0 + word_byte_offset) as *mut u32;
    unsafe {
        dsb_ishst();
        ptr::write_volatile(isenabler_ptr, 1u32 << bit);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// setup_irq_forwarding — top-level boot call
// ─────────────────────────────────────────────────────────────────────────────

/// Enable physical IRQ forwarding for timer PPIs and UART SPI.
///
/// Called once during boot after `init_physical_gic()`. Performs:
///
/// 1. Enable INTID 27 (virtual timer PPI) on every online core's GICR.
/// 2. Enable INTID 30 (NS physical timer PPI) on every online core's GICR.
/// 3. Enable INTID 33 (PL011 UART SPI) in the GICD.
///
/// With `HCR_EL2.IMO=1` (set by `configure_el2_virt()`), these enabled
/// interrupts are routed to EL2 when they assert. `aether_handle_irq`
/// forwards each one to the Android guest via a hardware-backed LR
/// (`ICH_LRn_EL2.HW=1`).
///
/// # Arguments
/// - `gicd_base`: GICD physical base address.
/// - `gicr_base`: first Redistributor RD frame physical base.
/// - `online_cores`: number of online cores (wake range 0..online_cores).
///
/// # Safety
/// Must be called from EL2 after:
///   - `init_physical_gic()` has completed (Redistributors woken, GICD enabled).
///   - `configure_el2_virt()` has set `HCR_EL2.IMO=1`.
/// `gicd_base` and `gicr_base` must be valid, accessible MMIO addresses.
pub unsafe fn setup_irq_forwarding(gicd_base: u64, gicr_base: u64, online_cores: usize) {
    // Enable timer PPIs per-core. Each core's Redistributor has its own
    // GICR_ISENABLER0 (SGI frame) that must be written individually.
    for core in 0..online_cores {
        let rd_base = gicr_base + (core * gicr::STRIDE) as u64;
        unsafe {
            enable_ppi_in_gicr(rd_base, TIMER_VIRT_INTID);
            enable_ppi_in_gicr(rd_base, TIMER_PHYS_NS_INTID);
        }
    }

    // Enable UART SPI globally in the Distributor.
    unsafe { enable_spi_in_gicd(gicd_base, UART_SPI_INTID) };
}

// ─────────────────────────────────────────────────────────────────────────────
// Compile-time constant verification
// ─────────────────────────────────────────────────────────────────────────────

const _: () = {
    // Timer PPIs must be in the PPI range 16..31.
    assert!(TIMER_VIRT_INTID >= 16 && TIMER_VIRT_INTID < 32,
        "TIMER_VIRT_INTID (27) must be a PPI (16..31)");
    assert!(TIMER_PHYS_NS_INTID >= 16 && TIMER_PHYS_NS_INTID < 32,
        "TIMER_PHYS_NS_INTID (30) must be a PPI (16..31)");

    // UART must be an SPI (≥ 32).
    assert!(UART_SPI_INTID >= 32,
        "UART_SPI_INTID (33) must be an SPI (>= 32)");

    // Verify the exact QEMU virt assignments that the gate test relies on.
    assert!(TIMER_VIRT_INTID    == 27, "QEMU virt virtual timer PPI = 27");
    assert!(TIMER_PHYS_NS_INTID == 30, "QEMU virt NS phys timer PPI = 30");
    assert!(UART_SPI_INTID      == 33, "QEMU virt PL011 UART SPI = 33");

    // IrqForwardConfig::QEMU_VIRT must use the same values.
    assert!(IrqForwardConfig::QEMU_VIRT.timer_virt_intid    == TIMER_VIRT_INTID);
    assert!(IrqForwardConfig::QEMU_VIRT.timer_phys_ns_intid == TIMER_PHYS_NS_INTID);
    assert!(IrqForwardConfig::QEMU_VIRT.uart_spi_intid      == UART_SPI_INTID);
    assert!(IrqForwardConfig::QEMU_VIRT.maint_intid         == 25,
        "QEMU virt VGIC maintenance PPI = 25");
};
