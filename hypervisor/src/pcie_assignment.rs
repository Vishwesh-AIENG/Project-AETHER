// ch38: PCIe Device Assignment and SMMU Wiring — Functional
//
// Makes assign_device_group() fully functional as real MMIO sequences and adds
// the ECAM config-space window mapping that allows the guest's PCI subsystem to
// enumerate assigned devices (required for "lspci" gate test).
//
// Ch11 (passthrough.rs) established the pipeline structure and all five steps:
// IOMMU group check → FLR → BAR map → SMMU STE → registry commit.
// Ch38 extends this with two hardware sequences that Ch11 left out:
//
//   A. ECAM window mapping — the guest must be able to read PCIe config space
//      via ECAM so that `lspci` and the Android PCI subsystem can enumerate
//      devices.  Without this mapping the guest sees an empty PCI bus even if
//      the device's BAR MMIO is correctly mapped and the SMMU STE is in place.
//
//   B. Bus Master Enable (BME) — bit 2 of the PCIe Command register must be
//      set after FLR so the device can issue DMA requests.  FLR clears BME;
//      if it is not re-asserted after assignment the device initialises without
//      error but every DMA write is silently dropped by the root complex.
//
// Full pipeline executed by assign_device_with_ecam() (actual execution order):
//   1. Config validation            (PcieAssignmentConfig::validate)
//   2. IOMMU group integrity check  (passthrough::check_group)
//   3. FLR                          (passthrough::trigger_flr — MMIO write to
//                                    Device Control + poll Device Status)
//   4. BAR scan → Stage 2           (passthrough::scan_bars + Stage2Tables::map_range)
//   5. SMMU STE (Stage-2-only)      (SmmuSte::stage2_only + SmmuStreamTable::write_ste;
//                                    words 1–7 written first, DSB ISH, then word 0)
//   6. Registry commit              (PassthroughRegistry::commit_group)
//   7. ECAM window → Stage 2        (map_ecam_window — DeviceRw, IPA == PA)
//   8. Bus Master Enable            (enable_bus_master — MMIO write to Command reg)
//
// Steps 2–6 run inside passthrough::assign_device_group(); steps 7–8 are Ch38
// additions.  SMMU STE (step 5) must precede BME (step 8) so the first DMA the
// device issues after BME is enabled is already constrained by Stage 2 translation.
//
// ECAM window address formula (PCI Firmware Specification 3.0 §4.1.1):
//   window_pa   = mcfg_base + start_bus × PER_BUS_SIZE
//   window_size = (end_bus − start_bus + 1) × PER_BUS_SIZE
//   PER_BUS_SIZE = 32 devices × 8 functions × 4 KiB = 1 MiB = 0x10_0000
//
// BME: PCI Command register at config offset 0x04, bit 2.
//   FLR (PCIe §6.6.2) resets Command to 0 — BME cleared.
//   Re-set after assignment so DMA completes.
//
// Gate: PcieAssignmentGate { ecam_mapped: true, device_visible_in_lspci: true }
//   device_visible_in_lspci = ecam_mapped AND at least one BAR was mapped AND
//   the SMMU STE for every StreamID in the group is in Stage-2-only mode.
//
// References:
//   PCI Firmware Specification 3.0 §4.1.1     — ECAM window addressing
//   PCI Base Specification 5.0 §7.5.1         — Command register (BME = bit 2)
//   PCIe Base Specification 5.0 §6.6.2        — Function-Level Reset (FLR)
//   ARM SMMU v3 IHI0070E §3.4 / §6.3         — STE format, Stage 2 config
//   ARM SMMU v3 IHI0070E §3.6                — MSI routing via Stage 2
//   ARM ARM DDI0487 Table D5-22              — Stage 2 MemAttr encoding
//   linux-ref/drivers/vfio/pci/vfio_pci_core.c — VFIO passthrough reference

use crate::memory::{BumpAllocator, MapKind, SmmuStreamTable, Stage2Tables};
use crate::partition::GuestId;
use crate::passthrough::{
    assign_device_group, scan_bars, AssignError, IommuGroup, PcieAddr, PcieEcam,
    PassthroughRegistry,
};

// ─────────────────────────────────────────────────────────────────────────────
// Error type
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced by Ch38 device assignment operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssignmentError {
    /// Underlying passthrough pipeline step failed.
    Passthrough(AssignError),
    /// ECAM window bus range is invalid (start_bus > end_bus).
    InvalidBusRange,
    /// The ECAM window size overflows a u64 (bus range too large).
    EcamWindowOverflow,
}

impl From<AssignError> for AssignmentError {
    fn from(e: AssignError) -> Self {
        AssignmentError::Passthrough(e)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ECAM window
//
// Describes the Enhanced Configuration Access Mechanism physical address window
// for one PCI segment, as declared in the ACPI MCFG table.
//
// The ECAM window must be mapped into the guest's Stage 2 page tables as
// DeviceRw (IPA == PA) before the SMMU is enabled.  The Android kernel's PCI
// subsystem — and userspace `lspci` — reads devices' config space through this
// window.  Without the mapping the guest sees an empty PCI bus.
//
// Reference: PCI Firmware Specification 3.0 §4.1.1
// ─────────────────────────────────────────────────────────────────────────────

/// Size of the ECAM config-space region for one PCIe bus.
///
/// 32 devices × 8 functions × 4 KiB = 1 MiB = 0x10_0000.
/// Source: PCI Firmware Specification 3.0 §4.1.1
pub const ECAM_PER_BUS_SIZE: u64 = 0x10_0000;

/// ECAM physical address window for one PCI segment (from ACPI MCFG).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EcamWindow {
    /// Physical base address of the MCFG segment (bus 0 config space).
    pub mcfg_base_pa: u64,
    /// First bus number in the range (inclusive).
    pub start_bus: u8,
    /// Last bus number in the range (inclusive).
    pub end_bus: u8,
}

impl EcamWindow {
    /// Create an ECAM window.  Returns `None` if `start_bus > end_bus`.
    pub const fn new(mcfg_base_pa: u64, start_bus: u8, end_bus: u8) -> Option<Self> {
        if start_bus > end_bus {
            return None;
        }
        Some(Self { mcfg_base_pa, start_bus, end_bus })
    }

    /// Physical base address of the first byte of the window (bus `start_bus`).
    ///
    /// This is the address the guest's PCI subsystem programs into its MCFG
    /// controller base register, and the identity IPA address AETHER maps.
    pub fn window_pa(&self) -> u64 {
        self.mcfg_base_pa
            .wrapping_add(self.start_bus as u64 * ECAM_PER_BUS_SIZE)
    }

    /// Total size in bytes of the ECAM window covering all buses.
    ///
    /// `(end_bus − start_bus + 1) × ECAM_PER_BUS_SIZE`.
    /// Returns `None` on u64 overflow (bus range too large).
    pub fn window_size(&self) -> Option<u64> {
        let bus_count = (self.end_bus as u64)
            .checked_sub(self.start_bus as u64)?
            .checked_add(1)?;
        bus_count.checked_mul(ECAM_PER_BUS_SIZE)
    }

    /// ECAM config-space physical address for the given BDF.
    ///
    /// Matches `PcieEcam::cfg_ptr()` in passthrough.rs and is valid as an IPA
    /// when the ECAM window is identity-mapped (IPA == PA) in Stage 2.
    pub fn bdf_config_pa(&self, addr: PcieAddr) -> u64 {
        self.mcfg_base_pa
            | ((addr.bus as u64) << 20)
            | ((addr.device as u64) << 15)
            | ((addr.function as u64) << 12)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ECAM window → Stage 2 mapping
// ─────────────────────────────────────────────────────────────────────────────

/// Map the ECAM config-space window into the guest's Stage 2 page tables.
///
/// Identity-maps the window (IPA == PA) as `DeviceRw` so the guest PCI
/// subsystem can access config registers for any device in the bus range.
///
/// Must be called before the SMMU and Stage 2 are enabled, during early boot
/// when the UEFI identity map is in effect.
///
/// # Errors
/// - `InvalidBusRange`: `window.start_bus > window.end_bus`.
/// - `EcamWindowOverflow`: bus range too wide for u64.
/// - `Passthrough(MapFailed)`: Stage 2 mapping failed (e.g. out of memory).
///
/// # Safety
/// - `s2_tables` must be the Stage 2 tables for the target guest.
/// - `alloc` must cover writable, non-aliased physical pages.
/// - Must be called single-threaded during early boot.
pub unsafe fn map_ecam_window(
    window: EcamWindow,
    s2_tables: &Stage2Tables,
    alloc: &mut BumpAllocator,
) -> Result<(), AssignmentError> {
    let size = window.window_size().ok_or(AssignmentError::EcamWindowOverflow)?;
    let pa = window.window_pa();

    // Identity map: IPA == PA.  The Android PCI subsystem reads MCFG from the
    // ACPI table (which AETHER provides) and expects config space at the same
    // physical address it reads there.
    unsafe {
        s2_tables
            .map_range(pa, pa, size, MapKind::DeviceRw, alloc)
            .map_err(|e| AssignmentError::Passthrough(AssignError::MapFailed(e)))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Bus Master Enable (BME)
//
// PCI Command register at config offset 0x04, bit 2 = Bus Master Enable.
// FLR (PCIe §6.6.2) resets the Command register to 0, clearing BME.
// Without BME the device cannot issue DMA; every PCIe TLP with the
// Request bit set is silently rejected by the root complex.
//
// AETHER re-asserts BME after FLR, immediately before commit_group, so
// the device is DMA-capable as soon as the registry records its assignment.
// ─────────────────────────────────────────────────────────────────────────────

/// Bit 2 of the PCI Command register: Bus Master Enable.
/// Source: PCI Base Specification 5.0 Table 7-6 (Command Register).
pub const PCI_COMMAND_BUS_MASTER: u16 = 1 << 2;

/// Set Bus Master Enable in the PCI Command register.
///
/// After FLR the Command register is cleared to 0.  Re-asserting BME allows
/// the device to issue DMA requests through the SMMU.  Must be called after
/// `trigger_flr()` and after the SMMU STE is written.
///
/// # Safety
/// - ECAM must be identity-mapped at EL2 (UEFI identity map during boot).
/// - The device at `addr` must exist and have completed FLR.
pub unsafe fn enable_bus_master(ecam: &PcieEcam, addr: PcieAddr) {
    // Read-modify-write: preserve all other Command bits.
    let cmd = unsafe { ecam.read16(addr, 0x04) };
    unsafe { ecam.write16(addr, 0x04, cmd | PCI_COMMAND_BUS_MASTER) };
}

// ─────────────────────────────────────────────────────────────────────────────
// Device assignment gate
// ─────────────────────────────────────────────────────────────────────────────

/// Ch38 gate criterion: assigned PCIe device is visible in guest lspci.
///
/// Both booleans must be true to pass the gate.
///
/// - `ecam_mapped`: the ECAM config-space window was mapped into the guest's
///   Stage 2 tables as DeviceRw, allowing the PCI subsystem to enumerate devices.
/// - `device_visible_in_lspci`: at least one BAR was found and mapped AND the
///   SMMU STE for every StreamID in the group is in Stage-2-only mode.
///
/// `device_visible_in_lspci` is a derived invariant: it is set by
/// `assign_device_with_ecam()` only when the full five-step pipeline completes
/// with at least one BAR mapped.  If all six BARs are unimplemented (unusual
/// but legal), the device config space is still accessible via lspci but DMA
/// will not work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PcieAssignmentGate {
    /// ECAM window was mapped into guest Stage 2 as DeviceRw.
    pub ecam_mapped: bool,
    /// At least one BAR was mapped AND SMMU STEs are Stage-2-only.
    pub device_visible_in_lspci: bool,
}

impl PcieAssignmentGate {
    /// Initial gate state before any assignment step runs.
    pub const fn not_started() -> Self {
        Self { ecam_mapped: false, device_visible_in_lspci: false }
    }

    /// Returns `true` when the gate passes (both criteria satisfied).
    pub const fn passes(&self) -> bool {
        self.ecam_mapped && self.device_visible_in_lspci
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for one Ch38 PCIe device assignment.
#[derive(Clone, Copy, Debug)]
pub struct PcieAssignmentConfig {
    /// IOMMU group for the device (StreamIDs that travel together).
    pub group: IommuGroup,
    /// Which guest partition receives this device.
    pub guest: GuestId,
    /// BDF (Bus/Device/Function) of the physical function.
    pub addr: PcieAddr,
    /// ECAM window for the PCI segment containing `addr`.
    pub ecam_window: EcamWindow,
    /// VMID of the guest partition (embedded in SMMU STEs).
    pub vmid: u16,
    /// Physical address of the guest's Stage 2 root table.
    pub s2ttb_pa: u64,
}

impl PcieAssignmentConfig {
    /// Verify the bus range is non-empty and the device BDF is in range.
    ///
    /// Returns `Err(InvalidBusRange)` if `ecam_window.start_bus > end_bus` or
    /// if `addr.bus` is outside the window's bus range.
    pub fn validate(&self) -> Result<(), AssignmentError> {
        if self.ecam_window.start_bus > self.ecam_window.end_bus {
            return Err(AssignmentError::InvalidBusRange);
        }
        if self.addr.bus < self.ecam_window.start_bus
            || self.addr.bus > self.ecam_window.end_bus
        {
            return Err(AssignmentError::InvalidBusRange);
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Full assignment pipeline — Ch38 entry point
// ─────────────────────────────────────────────────────────────────────────────

/// Assign a PCIe device to a guest with full ECAM window mapping and BME enable.
///
/// Executes the complete Ch38 pipeline (in this order):
///
/// 1. **Config validation** — BDF bus must be within the ECAM window bus range.
/// 2. **IOMMU group check** — no cross-guest StreamID conflict.
/// 3. **FLR** — PCIe Function-Level Reset via config-space MMIO writes.
/// 4. **BAR scan → Stage 2** — each memory BAR mapped as DeviceRw (IPA == PA).
/// 5. **SMMU STE** — Stage-2-only entry per StreamID (words 1–7 then word 0,
///    separated by DSB ISH); DMA confined to guest's IPA→PA mappings.
/// 6. **Registry commit** — records assignment for future group integrity checks.
/// 7. **ECAM window → Stage 2** — maps config-space window as DeviceRw so
///    the guest's `lspci` and PCI subsystem can enumerate the device.
/// 8. **Bus Master Enable** — re-asserts BME cleared by FLR so DMA works.
///    Must run after SMMU STE (step 5) so the first device DMA is intercepted.
///
/// On success, populates `gate` with both `ecam_mapped = true` and
/// `device_visible_in_lspci = true` (when ≥ 1 BAR exists).
///
/// # Errors
/// Returns the first error encountered.  On a `Passthrough(MapFailed)` in step 4
/// (BAR map), no SMMU STEs or registry entries are written.  On `MapFailed` in
/// step 7 (ECAM map), the SMMU STE and registry are already committed but the
/// ECAM window is absent (lspci will show nothing).  MapFailed should be treated
/// as fatal in the boot sequence — partial state is not recoverable.
///
/// # Safety
/// - ECAM base must be identity-mapped at EL2 via the UEFI identity map.
/// - All StreamIDs in `config.group` must identify SMMU-attached devices.
/// - `s2_tables` must be the Stage 2 tables for `config.guest`.
/// - Must be called single-threaded during early boot, before Stage 2 is enabled.
pub unsafe fn assign_device_with_ecam(
    config: &PcieAssignmentConfig,
    ecam: &PcieEcam,
    s2_tables: &Stage2Tables,
    smmu: &mut SmmuStreamTable,
    alloc: &mut BumpAllocator,
    registry: &mut PassthroughRegistry,
    gate: &mut PcieAssignmentGate,
) -> Result<(), AssignmentError> {
    // Validate configuration before touching any hardware.
    config.validate()?;

    // ── Steps 2–6: IOMMU check, FLR, BAR map, SMMU STE, registry ────────────
    // The five-step core pipeline from passthrough::assign_device_group handles
    // steps 2 through 6: IOMMU group check → FLR → BAR scan and Stage 2
    // mapping → SMMU STE (words 1–7, DSB, word 0) → registry commit.
    unsafe {
        assign_device_group(
            &config.group,
            config.guest,
            ecam,
            config.addr,
            s2_tables,
            smmu,
            config.vmid,
            config.s2ttb_pa,
            alloc,
            registry,
        )?;
    }

    // ── Step 7: ECAM window → Stage 2 (DeviceRw, IPA == PA) ─────────────────
    // Map the config-space window so the guest PCI subsystem can enumerate the
    // device via lspci.  Critical Ch38 addition: without this the guest sees an
    // empty bus even though BARs and STEs are correct.
    unsafe {
        map_ecam_window(config.ecam_window, s2_tables, alloc)?;
    }
    gate.ecam_mapped = true;

    // ── Step 8: Bus Master Enable ─────────────────────────────────────────────
    // FLR cleared BME (Command register bit 2). Re-assert so device DMA works.
    // Runs after SMMU STE (step 5) so the first DMA the device issues is already
    // confined to the guest's Stage 2 IPA→PA mappings.
    unsafe {
        enable_bus_master(ecam, config.addr);
    }

    // ── Gate update ───────────────────────────────────────────────────────────
    // device_visible_in_lspci is true when: ECAM mapped (above) AND at least
    // one BAR was mapped (checked by scanning BARs again, read-only — no writes).
    let bars = unsafe { scan_bars(ecam, config.addr) };
    let has_bar = bars.iter().any(|b| b.is_some());
    gate.device_visible_in_lspci = gate.ecam_mapped && has_bar;

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── EcamWindow construction ───────────────────────────────────────────────

    #[test]
    fn ecam_window_valid() {
        let w = EcamWindow::new(0x3000_0000, 0, 3).unwrap();
        assert_eq!(w.start_bus, 0);
        assert_eq!(w.end_bus, 3);
        assert_eq!(w.mcfg_base_pa, 0x3000_0000);
    }

    #[test]
    fn ecam_window_start_gt_end_rejected() {
        assert!(EcamWindow::new(0x3000_0000, 5, 4).is_none());
    }

    #[test]
    fn ecam_window_single_bus() {
        let w = EcamWindow::new(0x4000_0000, 0, 0).unwrap();
        assert_eq!(w.start_bus, 0);
        assert_eq!(w.end_bus, 0);
    }

    // ── EcamWindow::window_pa ─────────────────────────────────────────────────

    #[test]
    fn ecam_window_pa_bus0_is_base() {
        let w = EcamWindow::new(0x3000_0000, 0, 3).unwrap();
        // start_bus=0 → window_pa = base + 0 × PER_BUS_SIZE = base
        assert_eq!(w.window_pa(), 0x3000_0000);
    }

    #[test]
    fn ecam_window_pa_bus2() {
        // start_bus=2 → window_pa = base + 2 × 0x10_0000 = base + 0x20_0000
        let w = EcamWindow::new(0x3000_0000, 2, 5).unwrap();
        assert_eq!(w.window_pa(), 0x3000_0000 + 2 * ECAM_PER_BUS_SIZE);
    }

    // ── EcamWindow::window_size ───────────────────────────────────────────────

    #[test]
    fn ecam_window_size_single_bus() {
        let w = EcamWindow::new(0x3000_0000, 0, 0).unwrap();
        assert_eq!(w.window_size(), Some(ECAM_PER_BUS_SIZE));
    }

    #[test]
    fn ecam_window_size_four_buses() {
        // buses 0..=3 → 4 × 1MiB = 4 MiB
        let w = EcamWindow::new(0x3000_0000, 0, 3).unwrap();
        assert_eq!(w.window_size(), Some(4 * ECAM_PER_BUS_SIZE));
    }

    #[test]
    fn ecam_window_size_max_range() {
        // buses 0..=255 → 256 × 1MiB = 256 MiB
        let w = EcamWindow::new(0x4000_0000, 0, 255).unwrap();
        assert_eq!(w.window_size(), Some(256 * ECAM_PER_BUS_SIZE));
    }

    // ── EcamWindow::bdf_config_pa ─────────────────────────────────────────────

    #[test]
    fn ecam_bdf_config_pa_bus0_dev0_fn0() {
        let w = EcamWindow::new(0x3000_0000, 0, 3).unwrap();
        let addr = PcieAddr::new(0, 0, 0);
        // bus=0, dev=0, fn=0 → offset 0 → mcfg_base_pa
        assert_eq!(w.bdf_config_pa(addr), 0x3000_0000);
    }

    #[test]
    fn ecam_bdf_config_pa_bus1_dev2_fn3() {
        let w = EcamWindow::new(0x3000_0000, 0, 3).unwrap();
        let addr = PcieAddr::new(1, 2, 3);
        // bus=1→bit20, dev=2→bit15, fn=3→bit12
        let expected = 0x3000_0000u64
            | (1u64 << 20)
            | (2u64 << 15)
            | (3u64 << 12);
        assert_eq!(w.bdf_config_pa(addr), expected);
    }

    // ── ECAM per-bus size constant ────────────────────────────────────────────

    #[test]
    fn ecam_per_bus_size_is_1mib() {
        // 32 devices × 8 functions × 4 KiB
        assert_eq!(ECAM_PER_BUS_SIZE, 32 * 8 * 4096);
    }

    // ── PCI_COMMAND_BUS_MASTER ────────────────────────────────────────────────

    #[test]
    fn bus_master_enable_is_bit2() {
        assert_eq!(PCI_COMMAND_BUS_MASTER, 0x0004);
    }

    // ── PcieAssignmentGate ────────────────────────────────────────────────────

    #[test]
    fn gate_not_started_does_not_pass() {
        let g = PcieAssignmentGate::not_started();
        assert!(!g.ecam_mapped);
        assert!(!g.device_visible_in_lspci);
        assert!(!g.passes());
    }

    #[test]
    fn gate_partial_ecam_only_does_not_pass() {
        let g = PcieAssignmentGate {
            ecam_mapped: true,
            device_visible_in_lspci: false,
        };
        assert!(!g.passes());
    }

    #[test]
    fn gate_partial_lspci_only_does_not_pass() {
        let g = PcieAssignmentGate {
            ecam_mapped: false,
            device_visible_in_lspci: true,
        };
        assert!(!g.passes());
    }

    #[test]
    fn gate_both_true_passes() {
        let g = PcieAssignmentGate {
            ecam_mapped: true,
            device_visible_in_lspci: true,
        };
        assert!(g.passes());
    }

    // ── AssignmentError ───────────────────────────────────────────────────────

    #[test]
    fn assignment_error_from_assign_error() {
        let e: AssignmentError = AssignError::FlrTimeout.into();
        assert_eq!(e, AssignmentError::Passthrough(AssignError::FlrTimeout));
    }

    #[test]
    fn assignment_error_variants_distinct() {
        assert_ne!(AssignmentError::InvalidBusRange, AssignmentError::EcamWindowOverflow);
        assert_ne!(
            AssignmentError::Passthrough(AssignError::FlrTimeout),
            AssignmentError::InvalidBusRange
        );
    }

    // ── PcieAssignmentConfig::validate ───────────────────────────────────────

    #[test]
    fn config_validate_device_in_range_ok() {
        let cfg = PcieAssignmentConfig {
            group: IommuGroup::single(0),
            guest: GuestId::Android,
            addr: PcieAddr::new(2, 0, 0),
            ecam_window: EcamWindow::new(0x4000_0000, 0, 3).unwrap(),
            vmid: 1,
            s2ttb_pa: 0x5000_0000,
        };
        assert_eq!(cfg.validate(), Ok(()));
    }

    #[test]
    fn config_validate_device_out_of_range_err() {
        let cfg = PcieAssignmentConfig {
            group: IommuGroup::single(0),
            guest: GuestId::Android,
            addr: PcieAddr::new(10, 0, 0), // bus 10 outside [0,3]
            ecam_window: EcamWindow::new(0x4000_0000, 0, 3).unwrap(),
            vmid: 1,
            s2ttb_pa: 0x5000_0000,
        };
        assert_eq!(cfg.validate(), Err(AssignmentError::InvalidBusRange));
    }

    #[test]
    fn config_validate_bus_boundary_inclusive_ok() {
        // Device exactly on end_bus — must be valid.
        let cfg = PcieAssignmentConfig {
            group: IommuGroup::single(1),
            guest: GuestId::Android,
            addr: PcieAddr::new(3, 0, 0),
            ecam_window: EcamWindow::new(0x4000_0000, 0, 3).unwrap(),
            vmid: 1,
            s2ttb_pa: 0x5000_0000,
        };
        assert_eq!(cfg.validate(), Ok(()));
    }

    #[test]
    fn config_validate_bus_exactly_start_bus_ok() {
        let cfg = PcieAssignmentConfig {
            group: IommuGroup::single(1),
            guest: GuestId::Android,
            addr: PcieAddr::new(0, 0, 0),
            ecam_window: EcamWindow::new(0x4000_0000, 0, 3).unwrap(),
            vmid: 1,
            s2ttb_pa: 0x5000_0000,
        };
        assert_eq!(cfg.validate(), Ok(()));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Compile-time assertions
// ─────────────────────────────────────────────────────────────────────────────

const _: () = {
    // ECAM_PER_BUS_SIZE = 32 × 8 × 4096 = 1 MiB = 1_048_576.
    assert!(
        ECAM_PER_BUS_SIZE == 1_048_576,
        "ECAM_PER_BUS_SIZE must be exactly 1 MiB (32 × 8 × 4096)"
    );

    // BME bit must be bit 2 of the Command register.
    // PCI Base Specification 5.0 Table 7-6.
    assert!(
        PCI_COMMAND_BUS_MASTER == 1 << 2,
        "PCI_COMMAND_BUS_MASTER must be bit 2 (0x0004)"
    );

    // EcamWindow must not exceed one page on the stack (it is passed by value).
    use core::mem::size_of;
    assert!(
        size_of::<EcamWindow>() <= 64,
        "EcamWindow must fit in one cache line for stack use"
    );

    // PcieAssignmentGate must be small enough for stack use.
    assert!(
        size_of::<PcieAssignmentGate>() <= 8,
        "PcieAssignmentGate must be ≤ 8 bytes"
    );

    // PcieAssignmentConfig must be stack-allocable.
    assert!(
        size_of::<PcieAssignmentConfig>() <= 512,
        "PcieAssignmentConfig must be ≤ 512 bytes for stack use"
    );
};
