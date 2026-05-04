// ch11: The Passthrough Principle
//
// PCIe device assignment pipeline. Every DMA-capable device must be assigned
// exclusively to one guest. The pipeline has five mandatory steps, in order:
//
//   1. IOMMU group check  — all functions in a group go to the same guest;
//                           assigning half a group to different guests breaks DMA isolation
//   2. Function-Level Reset (FLR) — sanitise device state before assignment;
//                           any DMA addresses from a prior session are cleared
//   3. BAR mapping — device MMIO ranges mapped into guest Stage 2 as DeviceRw
//                    (identity: IPA == PA, so the guest driver can MMIO-map the real BAR)
//   4. SMMU STE — Stage 2-only translation for every StreamID in the group;
//                 NEVER Bypass — Bypass disables DMA isolation entirely
//   5. Registry update — records assignment for future group integrity checks
//
// MSI routing: with SMMU v3 Stage 2-only translation, device MSI writes go
// through Stage 2 like any other DMA. The caller must map the GIC ITS frame
// in Stage 2 (via `map_gic_its_frame`) so MSI writes reach the physical GIC.
// This is frequently omitted and produces devices that initialise but never
// deliver interrupts. See `map_gic_its_frame` below.
//
// References:
//   PCIe Base Specification 5.0, §6.6.2        — Function-Level Reset
//   PCIe Base Specification 5.0, §7.5.3        — BAR encoding
//   PCIe Base Specification 5.0, §6.7 (SR-IOV) — virtual functions + IOMMU groups
//   PCI Firmware Specification 3.0, §4.1.1     — ECAM config space access
//   ARM SMMU v3 IHI0070E, §3.2.5               — IOMMU groups
//   ARM SMMU v3 IHI0070E, §3.6                 — MSI mapping
//   GICv3 Architecture Specification IHI0069   — ITS MSI frame (§5.2)
//   linux-ref/drivers/vfio/pci/vfio_pci_core.c — VFIO reference implementation

use crate::arm64::barriers::dsb_ish;
use crate::memory::{
    BumpAllocator, MapError, MapKind, SmmuSte, SmmuStreamTable, Stage2Tables,
    SMMU_MAX_STREAMS,
};
use crate::partition::GuestId;

// ─────────────────────────────────────────────────────────────────────────────
// Error type
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssignError {
    /// A StreamID in the IOMMU group exceeds `SMMU_MAX_STREAMS`.
    StreamIdOutOfRange,
    /// One or more StreamIDs are already assigned to a different guest.
    /// Assigning across group boundaries would break DMA isolation.
    IommuGroupConflict,
    /// FLR did not complete within the polling budget; device may be stuck.
    FlrTimeout,
    /// The PCIe Express capability was not found — device does not support FLR.
    FlrCapabilityNotFound,
    /// Stage 2 BAR or ITS-frame mapping failed.
    MapFailed(MapError),
}

// ─────────────────────────────────────────────────────────────────────────────
// PCIe address (BDF)
// ─────────────────────────────────────────────────────────────────────────────

/// PCIe Bus / Device / Function address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PcieAddr {
    pub bus:      u8,
    pub device:   u8,
    pub function: u8,
}

impl PcieAddr {
    pub const fn new(bus: u8, device: u8, function: u8) -> Self {
        Self { bus, device, function }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PCIe ECAM config-space accessor
//
// The Enhanced Configuration Access Mechanism maps 4KB of config space per
// PCIe function at:
//   ECAM_BASE + (bus << 20) | (device << 15) | (function << 12)
//
// The base address comes from the ACPI MCFG table (one entry per PCI segment).
// During early boot the UEFI identity map makes this physically accessible.
//
// Reference: PCI Firmware Specification 3.0, §4.1.1
// ─────────────────────────────────────────────────────────────────────────────

/// PCIe Enhanced Configuration Access Mechanism.
pub struct PcieEcam {
    base_pa: u64,
}

impl PcieEcam {
    /// Construct from the MCFG base address for one PCI segment.
    pub const fn new(base_pa: u64) -> Self {
        Self { base_pa }
    }

    fn cfg_ptr(&self, addr: PcieAddr, offset: u16) -> *mut u8 {
        let bdf = ((addr.bus as u64) << 20)
            | ((addr.device as u64) << 15)
            | ((addr.function as u64) << 12);
        (self.base_pa + bdf + offset as u64) as *mut u8
    }

    /// Read an 8-bit byte from PCIe config space.
    ///
    /// # Safety
    /// The ECAM base must be identity-mapped and accessible at EL2.
    pub unsafe fn read8(&self, addr: PcieAddr, offset: u16) -> u8 {
        unsafe { self.cfg_ptr(addr, offset).read_volatile() }
    }

    /// Read a 16-bit word (little-endian) from PCIe config space.
    ///
    /// # Safety
    /// Same as `read8`. `offset` must be 2-byte aligned.
    pub unsafe fn read16(&self, addr: PcieAddr, offset: u16) -> u16 {
        unsafe { (self.cfg_ptr(addr, offset) as *mut u16).read_volatile() }
    }

    /// Read a 32-bit dword (little-endian) from PCIe config space.
    ///
    /// # Safety
    /// Same as `read8`. `offset` must be 4-byte aligned.
    pub unsafe fn read32(&self, addr: PcieAddr, offset: u16) -> u32 {
        unsafe { (self.cfg_ptr(addr, offset) as *mut u32).read_volatile() }
    }

    /// Write a 16-bit word to PCIe config space.
    ///
    /// # Safety
    /// Same as `read8`.
    pub unsafe fn write16(&self, addr: PcieAddr, offset: u16, val: u16) {
        unsafe { (self.cfg_ptr(addr, offset) as *mut u16).write_volatile(val) }
    }

    /// Write a 32-bit dword to PCIe config space.
    ///
    /// # Safety
    /// Same as `read8`.
    pub unsafe fn write32(&self, addr: PcieAddr, offset: u16, val: u32) {
        unsafe { (self.cfg_ptr(addr, offset) as *mut u32).write_volatile(val) }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BAR scanning
//
// PCIe Base Specification §7.5.3 defines the BAR encoding:
//   bit[0] = 0 → memory BAR; bit[0] = 1 → I/O BAR (skipped)
//   bits[2:1] = 0b00 → 32-bit; bits[2:1] = 0b10 → 64-bit
//   bit[3] = prefetchable
//
// Size determination: write all-ones, read mask, size = ~(mask & ~0xF) + 1.
// The Command register's Memory Space Enable (bit 1) must be cleared while
// probing to prevent the device responding to the all-ones probe value.
// ─────────────────────────────────────────────────────────────────────────────

/// A single memory-mapped PCIe BAR — its physical address and aperture size.
///
/// I/O BARs are not represented (AETHER assigns MMIO BARs only).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BarDescriptor {
    /// Physical base address as programmed into the BAR.
    pub pa: u64,
    /// Aperture size in bytes.
    pub size: u64,
}

/// Scan all six BARs of a PCIe Type 0 function header.
///
/// Returns up to six `BarDescriptor` entries. Entries are `None` for:
/// - Empty or unimplemented BARs
/// - I/O BARs (not mapped into Stage 2)
/// - The high-word slot of a 64-bit BAR pair
///
/// The Command register is saved and restored around the probe writes.
///
/// # Safety
/// The ECAM base must be accessible. The device at `addr` must exist on the bus.
pub unsafe fn scan_bars(ecam: &PcieEcam, addr: PcieAddr) -> [Option<BarDescriptor>; 6] {
    let mut out = [None::<BarDescriptor>; 6];

    // Save Command, then clear Memory Space Enable (bit 1) and
    // Bus Master Enable (bit 2) while probing BAR sizes.
    let saved_cmd = unsafe { ecam.read16(addr, 0x04) };
    unsafe { ecam.write16(addr, 0x04, saved_cmd & !(0x06u16)) };
    dsb_ish();

    let mut i: usize = 0;
    while i < 6 {
        let bar_offset = 0x10u16 + (i as u16) * 4;
        let bar_lo = unsafe { ecam.read32(addr, bar_offset) };

        // Skip I/O BARs (bit 0 = 1).
        if bar_lo & 0x1 != 0 {
            i += 1;
            continue;
        }

        let is_64bit = (bar_lo >> 1) & 0x3 == 0x2;

        // Probe: write all-ones, read size mask, restore original value.
        unsafe { ecam.write32(addr, bar_offset, 0xFFFF_FFFF) };
        let mask_lo = unsafe { ecam.read32(addr, bar_offset) };
        unsafe { ecam.write32(addr, bar_offset, bar_lo) };

        // mask == 0 or all-ones means BAR not implemented.
        if mask_lo == 0 || mask_lo == 0xFFFF_FFFF {
            i += 1;
            continue;
        }

        let (pa, size) = if is_64bit && i + 1 < 6 {
            let bar_hi_off = 0x10u16 + ((i + 1) as u16) * 4;
            let bar_hi = unsafe { ecam.read32(addr, bar_hi_off) };

            unsafe { ecam.write32(addr, bar_hi_off, 0xFFFF_FFFF) };
            let mask_hi = unsafe { ecam.read32(addr, bar_hi_off) };
            unsafe { ecam.write32(addr, bar_hi_off, bar_hi) };

            let pa = ((bar_hi as u64) << 32) | ((bar_lo & !0xF) as u64);
            let full_mask = ((mask_hi as u64) << 32) | ((mask_lo & !0xF) as u64);
            let size = (!full_mask).wrapping_add(1);
            // High-word slot is consumed; leave out[i+1] = None.
            i += 2;
            (pa, size)
        } else {
            let pa = (bar_lo & !0xF) as u64;
            let size = (!(mask_lo & !0xF)).wrapping_add(1) as u64;
            i += 1;
            (pa, size)
        };

        if size > 0 {
            // Place at the start index of the BAR (i was already advanced above).
            out[i - if is_64bit { 2 } else { 1 }] = Some(BarDescriptor { pa, size });
        }
    }

    // Restore Command register.
    dsb_ish();
    unsafe { ecam.write16(addr, 0x04, saved_cmd) };
    dsb_ish();

    out
}

// ─────────────────────────────────────────────────────────────────────────────
// PCIe capability list walker
// ─────────────────────────────────────────────────────────────────────────────

/// PCI Capability ID for the PCIe Express capability structure.
pub const PCI_CAP_ID_PCIE: u8 = 0x10;

/// Find the config-space offset of a PCI capability by its ID.
///
/// Returns `None` if the device has no capability list, or if the requested
/// cap ID is not present.
///
/// # Safety
/// The ECAM base must be accessible. The device at `addr` must exist.
pub unsafe fn find_pci_cap(ecam: &PcieEcam, addr: PcieAddr, cap_id: u8) -> Option<u8> {
    // PCI Status register bit 4 = Capabilities List present.
    let status = unsafe { ecam.read16(addr, 0x06) };
    if status & (1 << 4) == 0 {
        return None;
    }

    // Cap list head pointer at offset 0x34; bottom two bits reserved.
    let mut ptr = unsafe { ecam.read8(addr, 0x34) } & !0x3u8;

    // Walk the singly-linked list. Cap offsets must be ≥ 0x40 (standard header
    // occupies 0x00–0x3F). Limit iterations to detect cycles or corrupt data.
    for _ in 0..48u8 {
        if ptr < 0x40 {
            break;
        }
        let id = unsafe { ecam.read8(addr, ptr as u16) };
        if id == cap_id {
            return Some(ptr);
        }
        let next = unsafe { ecap_next(ecam, addr, ptr) };
        if next == 0 {
            break;
        }
        ptr = next;
    }
    None
}

/// Read the Next Pointer field of a PCI capability at `cap_off`.
///
/// # Safety
/// `cap_off` must be a valid capability offset in config space.
#[inline]
unsafe fn ecap_next(ecam: &PcieEcam, addr: PcieAddr, cap_off: u8) -> u8 {
    let next = unsafe { ecam.read8(addr, cap_off as u16 + 1) };
    next & !0x3u8
}

// ─────────────────────────────────────────────────────────────────────────────
// Function-Level Reset (FLR)
//
// FLR resets the function to a clean state — all internal state, DMA engine
// addresses, and interrupt configuration are cleared. AETHER must perform FLR
// before assigning a device to any guest to prevent state leakage.
//
// Initiation: set bit 15 (Initiate FLR) of the Device Control register
//   (cap_off + 0x08 in the PCIe Express capability structure).
// Completion: poll bit 5 (Transactions Pending) of the Device Status register
//   (cap_off + 0x0A) until clear, or until the timeout is reached.
//
// Reference: PCIe Base Specification 5.0, §6.6.2
// Mandatory timeout: 100ms (PCIe spec requirement for completion).
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum poll iterations for FLR completion.
///
/// Each iteration executes one volatile PCIe config-space read (~100–500 ns
/// across ECAM). 500_000 iterations ≈ 50–250 ms — covers the 100ms spec limit.
const FLR_POLL_MAX: u32 = 500_000;

/// Initiate a PCIe Function-Level Reset and wait for it to complete.
///
/// Sets the Initiate FLR bit in Device Control and polls Transaction Pending
/// in Device Status until clear (device quiesced) or timeout.
///
/// **Must** be called before `assign_device_group` assigns any device to a
/// guest. Omitting FLR may allow the new guest to observe DMA buffer addresses
/// or interrupt state left by a previous guest.
///
/// # Errors
/// - `FlrCapabilityNotFound` — device has no PCIe capability; FLR undefined.
/// - `FlrTimeout` — Transaction Pending did not clear within the poll budget.
///
/// # Safety
/// - ECAM must be accessible at EL2 via the UEFI identity map.
/// - The device must be quiesced (no in-flight driver activity) before FLR.
pub unsafe fn trigger_flr(ecam: &PcieEcam, addr: PcieAddr) -> Result<(), AssignError> {
    let cap_off = unsafe { find_pci_cap(ecam, addr, PCI_CAP_ID_PCIE) }
        .ok_or(AssignError::FlrCapabilityNotFound)?;

    // Device Control register: cap_off + 0x08. Bit 15 = Initiate FLR.
    let devctl_off = cap_off as u16 + 0x08;
    let devctl = unsafe { ecam.read16(addr, devctl_off) };
    unsafe { ecam.write16(addr, devctl_off, devctl | (1u16 << 15)) };
    dsb_ish();

    // Device Status register: cap_off + 0x0A. Bit 5 = Transactions Pending.
    let devsta_off = cap_off as u16 + 0x0A;
    for _ in 0..FLR_POLL_MAX {
        let devsta = unsafe { ecam.read16(addr, devsta_off) };
        if devsta & (1u16 << 5) == 0 {
            return Ok(());
        }
    }

    Err(AssignError::FlrTimeout)
}

// ─────────────────────────────────────────────────────────────────────────────
// IOMMU group
//
// An IOMMU group is the minimum set of PCIe functions that share IOMMU
// resources (e.g., PCIe ATS peer-to-peer, TLP routing). Every function in
// a group must be assigned to the same guest. Assigning across a group
// boundary would allow one guest's DMA to reach another guest's memory.
//
// On Snapdragon X Elite, IOMMU groups are populated by walking the ACPI IORT
// table (discovered in Ch07 boot.rs). Each PCIe function's StreamID is derived
// from its Requester ID (RID = bus<<8 | device<<3 | function).
//
// Reference: ARM SMMU v3 IHI0070E §3.2.5
//            linux-ref/drivers/iommu/iommu.c (group membership rules)
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum StreamIDs in one IOMMU group.
///
/// An SR-IOV device's physical function + virtual functions typically form one
/// group. Snapdragon X Elite has no consumer SR-IOV device with > 16 VFs,
/// so 32 is generous headroom.
pub const MAX_GROUP_MEMBERS: usize = 32;

/// An IOMMU group: the set of StreamIDs that must be assigned together.
#[derive(Clone, Copy)]
pub struct IommuGroup {
    pub stream_ids: [u32; MAX_GROUP_MEMBERS],
    pub count: usize,
}

impl IommuGroup {
    /// Create a single-member group (most PCIe functions, no SR-IOV siblings).
    pub const fn single(stream_id: u32) -> Self {
        let mut ids = [0u32; MAX_GROUP_MEMBERS];
        ids[0] = stream_id;
        Self { stream_ids: ids, count: 1 }
    }

    /// Create a group from a slice. Returns `None` if `ids.len() > MAX_GROUP_MEMBERS`.
    pub fn from_slice(ids: &[u32]) -> Option<Self> {
        if ids.len() > MAX_GROUP_MEMBERS {
            return None;
        }
        let mut stream_ids = [0u32; MAX_GROUP_MEMBERS];
        stream_ids[..ids.len()].copy_from_slice(ids);
        Some(Self { stream_ids, count: ids.len() })
    }

    /// Iterate the active stream IDs in this group.
    pub fn ids(&self) -> &[u32] {
        &self.stream_ids[..self.count]
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Passthrough registry
//
// Tracks the guest assignment for every StreamID. Initialised to all-None at
// boot (unassigned). Used by `check_group` to enforce the invariant that no
// StreamID is ever assigned to two different guests.
// ─────────────────────────────────────────────────────────────────────────────

/// Assignment state for one StreamID slot.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SlotState {
    Unassigned,
    Android,
    Windows,
}

/// Tracks which guest each StreamID is assigned to.
///
/// At boot all StreamIDs are `Unassigned`. Devices not assigned will have
/// Abort STEs in the SMMU stream table (the all-zero default from Ch08).
pub struct PassthroughRegistry {
    slots: [SlotState; SMMU_MAX_STREAMS],
}

impl PassthroughRegistry {
    pub const fn new() -> Self {
        Self { slots: [SlotState::Unassigned; SMMU_MAX_STREAMS] }
    }

    /// Check whether the group can be assigned to `guest` without violating
    /// IOMMU group integrity.
    ///
    /// Returns `Ok(())` if every member is either unassigned or already
    /// assigned to `guest`. Returns `Err(IommuGroupConflict)` if any member
    /// is assigned to the other guest.
    pub fn check_group(
        &self,
        group: &IommuGroup,
        guest: GuestId,
    ) -> Result<(), AssignError> {
        for &sid in group.ids() {
            if sid as usize >= SMMU_MAX_STREAMS {
                return Err(AssignError::StreamIdOutOfRange);
            }
            let assigned_to = self.slots[sid as usize];
            let conflicts = match guest {
                GuestId::Android => assigned_to == SlotState::Windows,
                GuestId::Windows => assigned_to == SlotState::Android,
            };
            if conflicts {
                return Err(AssignError::IommuGroupConflict);
            }
        }
        Ok(())
    }

    /// Record that all StreamIDs in `group` are assigned to `guest`.
    ///
    /// Call only after `check_group` succeeds and all SMMU STEs are written.
    fn commit_group(&mut self, group: &IommuGroup, guest: GuestId) {
        let state = match guest {
            GuestId::Android => SlotState::Android,
            GuestId::Windows => SlotState::Windows,
        };
        for &sid in group.ids() {
            if (sid as usize) < SMMU_MAX_STREAMS {
                self.slots[sid as usize] = state;
            }
        }
    }

    /// Query the current assignment for a StreamID. Returns `None` if unassigned
    /// or out of range.
    pub fn query(&self, stream_id: u32) -> Option<GuestId> {
        if stream_id as usize >= SMMU_MAX_STREAMS {
            return None;
        }
        match self.slots[stream_id as usize] {
            SlotState::Unassigned => None,
            SlotState::Android    => Some(GuestId::Android),
            SlotState::Windows    => Some(GuestId::Windows),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MSI routing via Stage 2
//
// With SMMU v3 Stage 2-only translation, device MSI writes are translated
// through Stage 2 like any other DMA transaction. No separate SMMU MSI table
// is required — the GIC ITS frame simply needs to be mapped in Stage 2 so that
// MSI writes from passed-through devices reach the physical GIC ITS doorbell.
//
// If the ITS frame is NOT mapped in Stage 2, MSI writes from the device will
// fault and no MSI interrupts are ever delivered to the guest.
//
// For GICv3 with an ITS, the ITS translation register frame is typically at
// a fixed physical address from the ACPI MADT (or device tree). AETHER
// identity-maps it (IPA == PA) because the Android GIC driver programs the
// device with the physical ITS doorbell address.
//
// Reference: GICv3 IHI0069 §5.2 (ITS), ARM SMMU v3 IHI0070E §3.6 (MSI)
// ─────────────────────────────────────────────────────────────────────────────

/// A GIC ITS translation register frame to be mapped in Stage 2.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GicItsFrame {
    /// Physical (and IPA) base of the ITS translation register frame.
    pub pa: u64,
    /// Frame size in bytes. Typically 128 KiB (0x2_0000) per IHI0069 §8.15.
    pub size: u64,
}

/// Map the GIC ITS frame into a guest's Stage 2 table as DeviceRw.
///
/// This is required for any guest that will receive MSI interrupts from
/// passed-through PCIe devices. With the ITS frame identity-mapped in Stage 2,
/// device MSI writes (translated through Stage 2 by the SMMU) arrive at the
/// physical GIC ITS doorbell and interrupts are delivered normally.
///
/// Call this once per guest, before enabling the SMMU.
///
/// # Errors
/// Returns `AssignError::MapFailed` if the Stage 2 mapping fails (e.g., OOM).
///
/// # Safety
/// `s2_tables` must be the Stage 2 tables for the target guest. `alloc` must
/// cover writable, non-aliased physical pages.
pub unsafe fn map_gic_its_frame(
    its: GicItsFrame,
    s2_tables: &Stage2Tables,
    alloc: &mut BumpAllocator,
) -> Result<(), AssignError> {
    // Identity map: guest IPA == PA. The Android GIC driver programs the device
    // with the physical ITS doorbell; Stage 2 translates the SMMU MSI write to
    // the same PA. No remapping needed.
    unsafe {
        s2_tables
            .map_range(its.pa, its.pa, its.size, MapKind::DeviceRw, alloc)
            .map_err(AssignError::MapFailed)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Device assignment — the five-step pipeline
// ─────────────────────────────────────────────────────────────────────────────

/// Assign a PCIe function and its IOMMU group exclusively to a guest.
///
/// Executes the full five-step passthrough pipeline:
///
/// 1. **IOMMU group check** (`check_group`) — ensures no StreamID in `group`
///    is already assigned to a different guest. Failure: `IommuGroupConflict`.
///
/// 2. **FLR** (`trigger_flr`) — resets the function via PCIe FLR. Clears all
///    DMA addresses, interrupt programming, and internal state left by any
///    prior guest session. Failure: `FlrCapabilityNotFound` / `FlrTimeout`.
///
/// 3. **BAR mapping** (`scan_bars` + `Stage2Tables::map_range`) — maps each
///    memory BAR as `DeviceRw` in the guest's Stage 2 table (identity: IPA==PA).
///    The guest's CPU driver can then MMIO-map the device at its physical BAR
///    address. Failure: `MapFailed`.
///
/// 4. **SMMU STE** (`SmmuSte::stage2_only` + `SmmuStreamTable::write_ste`) —
///    writes a Stage 2-only STE for every StreamID in `group`. This restricts
///    the device's DMA to the same IPA→PA mappings as the guest CPU, preventing
///    DMA escapes into another guest's physical memory.
///    **Never Bypass** — Bypass disables DMA isolation entirely.
///
/// 5. **Registry commit** (`commit_group`) — records the assignment so future
///    group-integrity checks work correctly.
///
/// MSI routing is NOT part of this function. Call `map_gic_its_frame` once per
/// guest before enabling the SMMU.
///
/// # Arguments
/// - `group`     — IOMMU group (set of StreamIDs that travel together)
/// - `guest`     — the guest that will own the device
/// - `ecam`      — ECAM config-space accessor (from ACPI MCFG)
/// - `addr`      — BDF of the function to reset and scan
/// - `s2_tables` — Stage 2 page table for `guest`
/// - `smmu`      — SMMU stream table (shared across all guests)
/// - `vmid`      — VMID of `guest` (embedded in every STE)
/// - `s2ttb_pa`  — Stage 2 root table PA for `guest`
/// - `alloc`     — bump allocator for new Stage 2 page-table pages
/// - `registry`  — passthrough registry, updated on success
///
/// # Errors
/// Returns the first error encountered. On error, SMMU STEs and registry
/// entries are **not** written. BAR Stage 2 mappings installed before an error
/// are not rolled back (treat `MapFailed` as fatal in the boot sequence).
///
/// # Safety
/// - ECAM base must be identity-mapped at EL2 (UEFI identity map during boot).
/// - All StreamIDs in `group` must identify SMMU-attached devices.
/// - Must be called single-threaded during early boot, before the SMMU is enabled.
pub unsafe fn assign_device_group(
    group: &IommuGroup,
    guest: GuestId,
    ecam: &PcieEcam,
    addr: PcieAddr,
    s2_tables: &Stage2Tables,
    smmu: &mut SmmuStreamTable,
    vmid: u16,
    s2ttb_pa: u64,
    alloc: &mut BumpAllocator,
    registry: &mut PassthroughRegistry,
) -> Result<(), AssignError> {
    // ── Step 1: IOMMU group integrity check ───────────────────────────────────
    registry.check_group(group, guest)?;

    // ── Step 2: Function-Level Reset ──────────────────────────────────────────
    // All device state from any prior session is cleared before we expose the
    // device to the new guest. DMA addresses programmed by a prior guest's
    // driver will not survive FLR.
    unsafe { trigger_flr(ecam, addr)?; }

    // ── Step 3: BAR mapping ───────────────────────────────────────────────────
    // Each memory BAR is identity-mapped in Stage 2 as DeviceRw. The guest CPU
    // driver reads its physical BAR address from config space and MMIO-maps it;
    // Stage 2 (IPA==PA) lets those accesses through to the real hardware.
    let bars = unsafe { scan_bars(ecam, addr) };
    for bar in bars.iter().flatten() {
        unsafe {
            s2_tables
                .map_range(bar.pa, bar.pa, bar.size, MapKind::DeviceRw, alloc)
                .map_err(AssignError::MapFailed)?;
        }
    }

    // ── Step 4: SMMU STE — Stage 2-only (NEVER Bypass) ───────────────────────
    // CFG_S2_ONLY constrains device DMA to the same IPA→PA translation as the
    // guest CPU. Bypass (CFG_BYPASS) would let the device DMA to any physical
    // address — a complete defeat of memory isolation.
    let ste = SmmuSte::stage2_only(vmid, s2ttb_pa);
    for &sid in group.ids() {
        // Bounds guaranteed by check_group; assert is a safety net.
        assert!((sid as usize) < SMMU_MAX_STREAMS, "stream_id out of range");
        unsafe { smmu.write_ste(sid as usize, ste); }
    }

    // ── Step 5: Registry commit ───────────────────────────────────────────────
    registry.commit_group(group, guest);

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── IommuGroup ────────────────────────────────────────────────────────────

    #[test]
    fn iommu_group_single() {
        let g = IommuGroup::single(42);
        assert_eq!(g.count, 1);
        assert_eq!(g.ids(), &[42u32]);
    }

    #[test]
    fn iommu_group_from_slice() {
        let ids = [1u32, 2, 3, 7, 15];
        let g = IommuGroup::from_slice(&ids).unwrap();
        assert_eq!(g.count, ids.len());
        assert_eq!(g.ids(), &ids);
    }

    #[test]
    fn iommu_group_from_slice_too_large() {
        let ids = [0u32; MAX_GROUP_MEMBERS + 1];
        assert!(IommuGroup::from_slice(&ids).is_none());
    }

    #[test]
    fn iommu_group_from_slice_empty() {
        let g = IommuGroup::from_slice(&[]).unwrap();
        assert_eq!(g.count, 0);
        assert_eq!(g.ids(), &[]);
    }

    // ── PassthroughRegistry ───────────────────────────────────────────────────

    #[test]
    fn registry_initially_unassigned() {
        let r = PassthroughRegistry::new();
        assert_eq!(r.query(0), None);
        assert_eq!(r.query(255), None);
    }

    #[test]
    fn registry_query_out_of_range() {
        let r = PassthroughRegistry::new();
        assert_eq!(r.query(SMMU_MAX_STREAMS as u32), None);
        assert_eq!(r.query(u32::MAX), None);
    }

    #[test]
    fn registry_check_group_unassigned_ok() {
        let r = PassthroughRegistry::new();
        let g = IommuGroup::from_slice(&[0, 1, 2]).unwrap();
        assert_eq!(r.check_group(&g, GuestId::Android), Ok(()));
        assert_eq!(r.check_group(&g, GuestId::Windows), Ok(()));
    }

    #[test]
    fn registry_check_group_stream_id_out_of_range() {
        let r = PassthroughRegistry::new();
        let g = IommuGroup::single(SMMU_MAX_STREAMS as u32);
        assert_eq!(
            r.check_group(&g, GuestId::Android),
            Err(AssignError::StreamIdOutOfRange)
        );
    }

    #[test]
    fn registry_commit_and_query() {
        let mut r = PassthroughRegistry::new();
        let g = IommuGroup::from_slice(&[10, 11, 12]).unwrap();
        r.commit_group(&g, GuestId::Android);
        assert_eq!(r.query(10), Some(GuestId::Android));
        assert_eq!(r.query(11), Some(GuestId::Android));
        assert_eq!(r.query(12), Some(GuestId::Android));
        assert_eq!(r.query(9),  None);
    }

    #[test]
    fn registry_conflict_detected() {
        let mut r = PassthroughRegistry::new();
        // Assign stream 5 to Android.
        let g1 = IommuGroup::single(5);
        r.commit_group(&g1, GuestId::Android);

        // Group containing stream 5 cannot be assigned to Windows.
        let g2 = IommuGroup::from_slice(&[5, 6]).unwrap();
        assert_eq!(
            r.check_group(&g2, GuestId::Windows),
            Err(AssignError::IommuGroupConflict)
        );
    }

    #[test]
    fn registry_same_guest_no_conflict() {
        let mut r = PassthroughRegistry::new();
        let g = IommuGroup::from_slice(&[20, 21]).unwrap();
        r.commit_group(&g, GuestId::Android);
        // Re-assigning the same group to the same guest is not a conflict.
        assert_eq!(r.check_group(&g, GuestId::Android), Ok(()));
    }

    #[test]
    fn registry_different_groups_different_guests() {
        let mut r = PassthroughRegistry::new();
        let ga = IommuGroup::single(100);
        let gw = IommuGroup::single(200);
        r.commit_group(&ga, GuestId::Android);
        r.commit_group(&gw, GuestId::Windows);
        assert_eq!(r.query(100), Some(GuestId::Android));
        assert_eq!(r.query(200), Some(GuestId::Windows));
        // Non-overlapping groups do not conflict.
        assert_eq!(r.check_group(&gw, GuestId::Windows), Ok(()));
        assert_eq!(r.check_group(&ga, GuestId::Android), Ok(()));
    }

    // ── PcieAddr ──────────────────────────────────────────────────────────────

    #[test]
    fn pcie_addr_fields() {
        let a = PcieAddr::new(1, 2, 3);
        assert_eq!(a.bus, 1);
        assert_eq!(a.device, 2);
        assert_eq!(a.function, 3);
    }

    // ── GicItsFrame ───────────────────────────────────────────────────────────

    #[test]
    fn gic_its_frame_size_typical() {
        let its = GicItsFrame { pa: 0x0800_0000, size: 0x2_0000 };
        assert_eq!(its.size, 128 * 1024);
    }

    // ── AssignError is Debug + PartialEq ─────────────────────────────────────

    #[test]
    fn assign_error_variants_distinct() {
        assert_ne!(AssignError::StreamIdOutOfRange, AssignError::IommuGroupConflict);
        assert_ne!(AssignError::FlrTimeout, AssignError::FlrCapabilityNotFound);
        assert_eq!(
            AssignError::MapFailed(MapError::OutOfMemory),
            AssignError::MapFailed(MapError::OutOfMemory)
        );
        assert_ne!(
            AssignError::MapFailed(MapError::OutOfMemory),
            AssignError::MapFailed(MapError::AlreadyMapped)
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Compile-time assertions
// ─────────────────────────────────────────────────────────────────────────────

const _: () = {
    use core::mem::size_of;

    // IommuGroup must not be too large for stack use.
    assert!(
        size_of::<IommuGroup>() <= 256,
        "IommuGroup too large for stack"
    );

    // PassthroughRegistry must fit in a static (one byte per slot).
    assert!(
        size_of::<PassthroughRegistry>() <= 4096,
        "PassthroughRegistry exceeds one page"
    );

    // FLR bit position sanity.
    assert!(1u16 << 15 == 0x8000, "FLR Initiate bit must be bit 15");

    // PCIe Express cap ID.
    assert!(PCI_CAP_ID_PCIE == 0x10, "PCIe cap ID must be 0x10");

    // BAR base offset in Type 0 header.
    assert!(0x10u16 + 5 * 4 == 0x24, "BAR5 must be at config offset 0x24");
};
