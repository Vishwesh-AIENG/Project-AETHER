// ch39: GPU SR-IOV — Functional Enable
//
// Reads the SR-IOV Extended Capability from the Adreno GPU Physical Function
// (PF), enables two Virtual Functions (NumVFs = 2), maps each VF's BARs into
// the Android guest's Stage 2 page tables, configures SMMU STEs for DMA
// isolation, and registers both VF assignments in the GPU partition registry.
//
// Pipeline (7 steps, executed by assign_gpu_vfs()):
//   1. Find SR-IOV Extended Capability in PF extended config space (start 0x100)
//   2. Read MaxVFs, FirstVFOffset, VFStride; validate MaxVFs ≥ 2
//   3. Write NumVFs = 2; then set VF_Enable + VF_MSE in SRIOV_CTRL; DSB ISH
//   4. Compute VF BDF addresses (PF_BDF + FirstVFOffset + n × VFStride)
//   5. Map each VF's BARs into Stage 2 as DeviceRw (IPA == PA) via scan_bars
//   6. Configure SMMU STE per VF StreamID (Stage-2-only; write_ste enforces
//      words 1–7 → DSB ISH → word 0 ordering per IHI0070E §3.6)
//   7. Map ECAM config-space window covering VF BDFs; register in registry
//
// Gate: GpuSrIovGate { vendor_id_visible: true, vf_bars_mapped: true }
//   vendor_id_visible = ECAM window mapped for VF BDFs so the Android DRM
//                       subsystem can read Vendor ID 0x17CB (Qualcomm) from VF
//                       config space.  Direct gate: `cat /sys/class/drm/
//                       card0/device/vendor` must print `0x17cb` in Android.
//   vf_bars_mapped    = ≥1 BAR mapped in Stage 2 per enabled VF; required so
//                       the DRM driver's MMIO accesses do not Stage-2-fault.
//
// SR-IOV Extended Capability offsets from cap base (PCIe Base Spec 5.0 §9.3.3):
//   +0x00  Extended Cap Header: ID[15:0]=0x0010, Version[19:16], Next[31:20]
//   +0x04  SR-IOV Capabilities (u32, read-only)
//   +0x08  SR-IOV Control (u16)  bit0 = VF_Enable  bit3 = VF_MSE
//   +0x0A  SR-IOV Status (u16)
//   +0x0C  InitialVFs (u16, read-only)
//   +0x0E  TotalVFs / MaxVFs (u16, read-only hardware limit)
//   +0x10  NumVFs (u16, read-write — software-configured VF count)
//   +0x12  FunctionDependencyLink (u8)
//   +0x14  First VF Offset (u16, read-only)
//   +0x16  VF Stride (u16, read-only)
//   +0x1A  VF Device ID (u16, read-only)
//   +0x24  VF BAR 0 … +0x38  VF BAR 5
//
// Write order for enabling SR-IOV (PCIe Spec §9.3.3.3.2):
//   1. Write NumVFs BEFORE setting VF Enable (hardware requires this ordering).
//   2. Set VF_Enable + VF_MSE together in one 16-bit write to SRIOV_CTRL.
//   3. DSB ISH — ensure config writes are ordered before SMMU STE activation.
//
// Common mistake (from SKILLS.md): Reading NumVFs before writing it.
//   MaxVFs (= TotalVFs, offset +0x0E) is the read-only hardware limit.
//   NumVFs (offset +0x10) is the software-configured count — write this value.
//
// References:
//   PCIe Base Specification 5.0 §9.3.3     — SR-IOV Extended Capability
//   PCIe Base Specification 5.0 §9.3.3.3.2 — NumVFs / VF Enable write order
//   ARM SMMU v3 IHI0070E §3.4 / §3.6       — STE format and write ordering
//   Freedreno at gitlab.freedesktop.org/mesa/mesa — open-source Adreno driver
//   Qualcomm Vendor ID 0x17CB              — PCI-SIG assignment for Qualcomm

use crate::arm64::barriers::dsb_ish;
use crate::gpu::{GpuError, GpuPartitionRegistry, GpuVirtualFunction};
use crate::memory::{BumpAllocator, SmmuSte, SmmuStreamTable, Stage2Tables, SMMU_MAX_STREAMS};
use crate::partition::GuestId;
use crate::passthrough::{scan_bars, PcieAddr, PcieEcam};
use crate::pcie_assignment::{map_ecam_window, AssignmentError, EcamWindow};

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// PCI-SIG Vendor ID for Qualcomm.
///
/// Read from VF config space at offset 0x00 (Vendor ID register).
/// `cat /sys/class/drm/card0/device/vendor` inside Android must print `0x17cb`.
/// Source: PCI-SIG allocation; confirmed in Freedreno Mesa driver.
pub const QUALCOMM_VENDOR_ID: u16 = 0x17CB;

/// PCIe Extended Capability ID for SR-IOV.
/// Source: PCIe Base Specification 5.0, Table 9-17.
pub const SRIOV_EXT_CAP_ID: u16 = 0x0010;

/// Extended Configuration Space starts at offset 0x100 in PCIe config space.
/// Source: PCI Express Base Spec 5.0 §7.6.
pub const ECAP_START_OFFSET: u16 = 0x100;

/// Offset of the SR-IOV Control register within the SR-IOV Extended Capability.
/// bit 0 = VF Enable; bit 3 = VF MSE (Memory Space Enable).
pub const SRIOV_CTRL_OFF: u16 = 0x08;

/// Offset of TotalVFs (MaxVFs) register — the hardware-supported maximum.
/// Read-only.  Never confuse this with NumVFs (offset +0x10) which is writable.
pub const SRIOV_TOTAL_VF_OFF: u16 = 0x0E;

/// Offset of NumVFs register — the software-configured VF count.
/// Write this BEFORE setting VF Enable in SRIOV_CTRL (PCIe §9.3.3.3.2).
pub const SRIOV_NUM_VF_OFF: u16 = 0x10;

/// Offset of First VF Offset register within the SR-IOV Extended Capability.
/// Read-only.  BDF delta from PF to VF 0: VF0_BDF = PF_BDF + FirstVFOffset.
pub const SRIOV_FIRST_VF_OFFSET_OFF: u16 = 0x14;

/// Offset of VF Stride register within the SR-IOV Extended Capability.
/// Read-only.  BDF delta between consecutive VFs: VFn_BDF = VF0_BDF + n × VFStride.
pub const SRIOV_VF_STRIDE_OFF: u16 = 0x16;

/// SR-IOV Control: VF Enable (bit 0).  Activates the configured NumVFs VFs.
pub const SRIOV_CTRL_VF_ENABLE: u16 = 1 << 0;

/// SR-IOV Control: VF Memory Space Enable (bit 3).
/// Must be set alongside VF Enable so VF BAR MMIO regions respond to accesses.
pub const SRIOV_CTRL_VF_MSE: u16 = 1 << 3;

/// Number of VFs AETHER enables on the Adreno GPU.
/// VF 0 is assigned to Android; VF 1 reserved for future Windows partition.
pub const AETHER_GPU_NUM_VFS: u16 = 2;

/// VF index assigned to the Android partition.
pub const ANDROID_VF_INDEX: u16 = 0;

/// Adreno model identifier reported to the Android DRM driver.
pub const ADRENO_MODEL: &str = "Adreno 740";

// ─────────────────────────────────────────────────────────────────────────────
// Error type
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced by GPU SR-IOV enable operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuSrIovError {
    /// SR-IOV Extended Capability (ID=0x0010) not found in PF extended config space.
    SrIovCapNotFound,
    /// GPU's MaxVFs < AETHER_GPU_NUM_VFS; hardware cannot support required VF count.
    InsufficientVfs {
        /// MaxVFs reported by the hardware.
        max_vfs: u16,
    },
    /// No BARs found for a VF; VF config space likely unresponsive after enable.
    NoVfBarsFound,
    /// Stage 2 mapping failed for a VF BAR or for the ECAM config-space window.
    MapFailed(AssignmentError),
    /// GPU partition registry rejected the VF assignment.
    RegistryError(GpuError),
    /// A StreamID exceeds SMMU_MAX_STREAMS and cannot be used for an STE write.
    StreamIdOutOfRange,
}

impl From<GpuError> for GpuSrIovError {
    fn from(e: GpuError) -> Self {
        GpuSrIovError::RegistryError(e)
    }
}

impl From<AssignmentError> for GpuSrIovError {
    fn from(e: AssignmentError) -> Self {
        GpuSrIovError::MapFailed(e)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Gate
// ─────────────────────────────────────────────────────────────────────────────

/// Ch39 gate criterion: Android guest observes the Qualcomm Adreno GPU VF.
///
/// Both booleans must be true to pass the gate.
///
/// - `vendor_id_visible`: ECAM window is mapped for VF BDFs so the Android DRM
///   subsystem can read Vendor ID 0x17CB (Qualcomm) from VF config space.
///   The functional gate: `cat /sys/class/drm/card0/device/vendor` must
///   print `0x17cb` inside the Android guest.
///
/// - `vf_bars_mapped`: At least one BAR was found and mapped in Stage 2 for
///   VF 0 (Android's VF). Without BAR mappings, the DRM driver's MMIO
///   accesses take Stage-2 faults and the GPU never initialises.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GpuSrIovGate {
    /// ECAM window mapped for VF BDFs; Android can read Vendor ID 0x17CB.
    pub vendor_id_visible: bool,
    /// ≥1 BAR mapped in Stage 2 for the Android VF; DRM MMIO will not fault.
    pub vf_bars_mapped: bool,
}

impl GpuSrIovGate {
    /// Initial state before any pipeline step runs.
    pub const fn not_started() -> Self {
        Self { vendor_id_visible: false, vf_bars_mapped: false }
    }

    /// Returns `true` when both criteria are satisfied.
    pub const fn passes(&self) -> bool {
        self.vendor_id_visible && self.vf_bars_mapped
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the Ch39 GPU SR-IOV enable pipeline.
#[derive(Clone, Copy, Debug)]
pub struct GpuSrIovConfig {
    /// BDF of the Adreno GPU Physical Function in the PCIe config space.
    pub pf_addr: PcieAddr,
    /// ECAM window for the PCIe segment containing the GPU PF (and its VFs).
    pub ecam_window: EcamWindow,
    /// VMID of the Android guest partition (embedded in SMMU STEs).
    pub vmid: u16,
    /// Physical address of the Android guest's Stage 2 translation table root.
    pub s2ttb_pa: u64,
    /// SMMU StreamIDs for VF 0 (Android) and VF 1 (future Windows).
    /// Each StreamID maps to one SMMU STE entry.
    pub stream_ids: [u32; 2],
}

impl GpuSrIovConfig {
    /// Validate basic invariants before touching any hardware registers.
    ///
    /// Returns `Err` if the ECAM bus range is degenerate or the PF BDF falls
    /// outside the declared ECAM window.
    pub fn validate(&self) -> Result<(), GpuSrIovError> {
        if self.ecam_window.start_bus > self.ecam_window.end_bus {
            return Err(GpuSrIovError::MapFailed(AssignmentError::InvalidBusRange));
        }
        if self.pf_addr.bus < self.ecam_window.start_bus
            || self.pf_addr.bus > self.ecam_window.end_bus
        {
            return Err(GpuSrIovError::MapFailed(AssignmentError::InvalidBusRange));
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SR-IOV Extended Capability discovery
// ─────────────────────────────────────────────────────────────────────────────

/// Walk the PCIe Extended Capability list to find the SR-IOV Extended Cap.
///
/// Extended Capability headers are 4-byte DWORDs at 4-byte-aligned offsets in
/// the range [0x100, 0xFFC]:
///   bits [15:0]  = Extended Cap ID
///   bits [19:16] = Capability Version
///   bits [31:20] = Next Capability Offset (0 = end of list)
///
/// A header of all-zeros or 0xFFFF_FFFF means the device is absent or in
/// power-down; both terminate the walk.
///
/// Returns the config-space offset of the SR-IOV cap header, or `None`.
///
/// # Safety
/// - ECAM must be identity-mapped at EL2 via the UEFI identity map.
/// - The device at `pf_addr` must exist and respond to config-space reads.
unsafe fn find_sriov_ext_cap(ecam: &PcieEcam, pf_addr: PcieAddr) -> Option<u16> {
    let mut offset: u16 = ECAP_START_OFFSET;
    for _ in 0..48u8 {
        if offset < ECAP_START_OFFSET || offset > 0x0FFC {
            break;
        }
        let hdr = unsafe { ecam.read32(pf_addr, offset) };
        if hdr == 0 || hdr == 0xFFFF_FFFF {
            break;
        }
        let cap_id = (hdr & 0xFFFF) as u16;
        if cap_id == SRIOV_EXT_CAP_ID {
            return Some(offset);
        }
        let next = ((hdr >> 20) & 0xFFF) as u16;
        if next == 0 {
            break;
        }
        offset = next;
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// SR-IOV capability field reads
// ─────────────────────────────────────────────────────────────────────────────

/// Read MaxVFs, FirstVFOffset, and VFStride from the SR-IOV Extended Cap.
///
/// `cap_off` is the config-space offset returned by `find_sriov_ext_cap`.
///
/// Returns `(max_vfs, first_vf_offset, vf_stride)`.
///
/// # Safety
/// - ECAM must be accessible at EL2.
/// - `cap_off` must be a valid SR-IOV extended capability offset.
unsafe fn read_sriov_cap_fields(
    ecam: &PcieEcam,
    pf_addr: PcieAddr,
    cap_off: u16,
) -> (u16, u16, u16) {
    let max_vfs = unsafe { ecam.read16(pf_addr, cap_off + SRIOV_TOTAL_VF_OFF) };
    let first_vf_offset = unsafe { ecam.read16(pf_addr, cap_off + SRIOV_FIRST_VF_OFFSET_OFF) };
    let vf_stride = unsafe { ecam.read16(pf_addr, cap_off + SRIOV_VF_STRIDE_OFF) };
    (max_vfs, first_vf_offset, vf_stride)
}

// ─────────────────────────────────────────────────────────────────────────────
// VF enable
// ─────────────────────────────────────────────────────────────────────────────

/// Write NumVFs and enable SR-IOV on the GPU PF.
///
/// Write order mandated by PCIe Spec §9.3.3.3.2:
///   1. Write `num_vfs` to NumVFs (offset +0x10) FIRST.
///   2. Set VF_Enable + VF_MSE together in one write to SRIOV_CTRL (offset +0x08).
///   3. DSB ISH — ensure config writes complete before any SMMU STE activation.
///
/// VF_MSE (Memory Space Enable, bit 3) must be set so VF BAR MMIO regions
/// respond to accesses.  Without VF_MSE, BAR reads return all-ones.
///
/// # Safety
/// - ECAM must be accessible at EL2 via the UEFI identity map.
/// - `cap_off` must be the offset of the SR-IOV Extended Capability header.
/// - `num_vfs` must be ≤ MaxVFs (checked by the caller before this call).
unsafe fn enable_vfs(ecam: &PcieEcam, pf_addr: PcieAddr, cap_off: u16, num_vfs: u16) {
    // Step 1: NumVFs BEFORE VF Enable (spec-mandated ordering).
    unsafe { ecam.write16(pf_addr, cap_off + SRIOV_NUM_VF_OFF, num_vfs) };
    // Step 2: VF Enable + VF Memory Space Enable in one 16-bit write.
    unsafe {
        ecam.write16(
            pf_addr,
            cap_off + SRIOV_CTRL_OFF,
            SRIOV_CTRL_VF_ENABLE | SRIOV_CTRL_VF_MSE,
        )
    };
    // Step 3: Ordering fence — SMMU must observe config writes before VF DMA.
    dsb_ish();
}

// ─────────────────────────────────────────────────────────────────────────────
// VF BDF computation
// ─────────────────────────────────────────────────────────────────────────────

/// Compute the `PcieAddr` of VF `vf_index` from the PF address and SR-IOV fields.
///
/// BDF is packed as `(bus << 8) | (device << 3) | function` in a u16.
/// Formula: `VFn_BDF = PF_BDF + FirstVFOffset + vf_index × VFStride`
/// (wrapping u16 arithmetic per the PCIe spec — VFs may occupy a different bus).
///
/// Source: PCIe Base Spec 5.0 §9.3.3.6 (First VF Offset / VF Stride).
pub fn compute_vf_addr(
    pf_addr: PcieAddr,
    first_vf_offset: u16,
    vf_stride: u16,
    vf_index: u16,
) -> PcieAddr {
    let pf_bdf16: u16 = ((pf_addr.bus as u16) << 8)
        | ((pf_addr.device as u16) << 3)
        | (pf_addr.function as u16);
    let delta = first_vf_offset.wrapping_add(vf_index.wrapping_mul(vf_stride));
    let vf_bdf16 = pf_bdf16.wrapping_add(delta);
    PcieAddr::new(
        (vf_bdf16 >> 8) as u8,
        ((vf_bdf16 >> 3) & 0x1F) as u8,
        (vf_bdf16 & 0x07) as u8,
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// SMMU STE configuration per VF
// ─────────────────────────────────────────────────────────────────────────────

/// Write a Stage-2-only SMMU STE for one VF StreamID.
///
/// `SmmuStreamTable::write_ste` enforces the mandatory STE write order
/// (IHI0070E §3.6): words 1–7, DSB ISH, word 0 (Valid + Config last).
///
/// # Errors
/// Returns `GpuSrIovError::StreamIdOutOfRange` if `stream_id ≥ SMMU_MAX_STREAMS`.
///
/// # Safety
/// - `smmu` must be accessible at EL2 and must not be concurrently modified.
/// - Must be called before the SMMU is enabled so the STE transition is safe.
unsafe fn configure_vf_ste(
    smmu: &mut SmmuStreamTable,
    stream_id: u32,
    vmid: u16,
    s2ttb_pa: u64,
) -> Result<(), GpuSrIovError> {
    if stream_id as usize >= SMMU_MAX_STREAMS {
        return Err(GpuSrIovError::StreamIdOutOfRange);
    }
    let ste = SmmuSte::stage2_only(vmid, s2ttb_pa);
    unsafe { smmu.write_ste(stream_id as usize, ste) };
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// VF BAR mapping
// ─────────────────────────────────────────────────────────────────────────────

/// Map all memory BARs for one VF into the guest's Stage 2 page tables.
///
/// Uses `scan_bars` on the VF's BDF (via ECAM) to discover BAR base addresses
/// and sizes.  Each non-None BAR is identity-mapped (IPA == PA) as `DeviceRw`.
///
/// Returns `true` if at least one BAR was mapped (VF config space responsive),
/// `false` if all BARs are unimplemented (unusual but legal — the DRM driver
/// will initialise without MMIO access, which is an error for Adreno).
///
/// # Safety
/// - ECAM must be accessible at EL2 for the VF's BDF.
/// - `s2_tables` must be the Stage 2 tables for the Android guest.
/// - Must be called after VF Enable so VF config space is active.
unsafe fn map_vf_bars(
    ecam: &PcieEcam,
    vf_addr: PcieAddr,
    s2_tables: &Stage2Tables,
    alloc: &mut BumpAllocator,
) -> Result<bool, GpuSrIovError> {
    let bars = unsafe { scan_bars(ecam, vf_addr) };
    let mut mapped_any = false;
    for bar in bars.iter().flatten() {
        unsafe {
            s2_tables
                .map_range(bar.pa, bar.pa, bar.size, crate::memory::MapKind::DeviceRw, alloc)
                .map_err(|e| {
                    GpuSrIovError::MapFailed(
                        AssignmentError::Passthrough(crate::passthrough::AssignError::MapFailed(e)),
                    )
                })?
        };
        mapped_any = true;
    }
    Ok(mapped_any)
}

// ─────────────────────────────────────────────────────────────────────────────
// Full pipeline — Ch39 entry point
// ─────────────────────────────────────────────────────────────────────────────

/// Enable GPU SR-IOV, map VF BARs and ECAM into Stage 2, configure SMMU STEs.
///
/// Executes the complete Ch39 pipeline (in this order):
///
/// 1. **Config validation** — ECAM bus range non-empty; PF BDF inside range.
/// 2. **SR-IOV cap discovery** — walk extended cap list for ID 0x0010.
/// 3. **MaxVFs check** — hardware must support ≥ `AETHER_GPU_NUM_VFS` (2) VFs.
/// 4. **Enable VFs** — write NumVFs = 2, then SRIOV_CTRL = VF_Enable | VF_MSE;
///    DSB ISH; NumVFs written BEFORE VF Enable (PCIe §9.3.3.3.2).
/// 5. **VF BAR mapping** — for each of the 2 VFs: `scan_bars(vf_bdf)` then
///    identity-map each non-None BAR as DeviceRw in Stage 2.
/// 6. **SMMU STEs** — `SmmuSte::stage2_only` + `write_ste` per VF StreamID;
///    word ordering enforced inside `write_ste` (words 1–7 → DSB → word 0).
/// 7. **ECAM window** — identity-map the PCIe config-space window as DeviceRw
///    so the Android DRM subsystem can read VF Vendor ID (0x17CB = Qualcomm).
/// 8. **Registry** — register both VF assignments in `GpuPartitionRegistry`.
///
/// On success, sets `gate.vendor_id_visible = true` and `gate.vf_bars_mapped = true`.
///
/// # Errors
/// Returns the first error encountered.  On failure after step 4 (VFs enabled),
/// the GPU PF remains with SR-IOV enabled; this is recoverable only by a full
/// platform reset.  Treat any error from this function as fatal in the boot
/// sequence.
///
/// # Safety
/// - ECAM must be identity-mapped at EL2 via the UEFI identity map.
/// - `s2_tables` must be the Stage 2 tables for `GuestId::Android`.
/// - `alloc` must provide writable, non-aliased physical pages.
/// - `smmu` must not be concurrently accessed.
/// - Must be called single-threaded during early boot, before Stage 2 is enabled.
pub unsafe fn assign_gpu_vfs(
    config: &GpuSrIovConfig,
    ecam: &PcieEcam,
    s2_tables: &Stage2Tables,
    smmu: &mut SmmuStreamTable,
    alloc: &mut BumpAllocator,
    registry: &mut GpuPartitionRegistry,
    gate: &mut GpuSrIovGate,
) -> Result<(), GpuSrIovError> {
    // ── Step 1: Validate config ───────────────────────────────────────────────
    config.validate()?;

    // ── Step 2: Find SR-IOV Extended Capability in PF config space ────────────
    let cap_off = unsafe { find_sriov_ext_cap(ecam, config.pf_addr) }
        .ok_or(GpuSrIovError::SrIovCapNotFound)?;

    // ── Step 3: Read MaxVFs, FirstVFOffset, VFStride; validate MaxVFs ─────────
    let (max_vfs, first_vf_offset, vf_stride) =
        unsafe { read_sriov_cap_fields(ecam, config.pf_addr, cap_off) };
    if max_vfs < AETHER_GPU_NUM_VFS {
        return Err(GpuSrIovError::InsufficientVfs { max_vfs });
    }

    // ── Step 4: Write NumVFs = 2, then VF_Enable | VF_MSE; DSB ISH ───────────
    // NumVFs is written BEFORE VF Enable — PCIe Spec §9.3.3.3.2.
    // Failure to follow this order results in undefined VF count on real silicon.
    unsafe { enable_vfs(ecam, config.pf_addr, cap_off, AETHER_GPU_NUM_VFS) };

    // ── Step 5: Map VF BARs into Stage 2 ─────────────────────────────────────
    let mut all_vfs_have_bars = true;
    for vf_index in 0..AETHER_GPU_NUM_VFS {
        let vf_addr = compute_vf_addr(config.pf_addr, first_vf_offset, vf_stride, vf_index);
        let has_bar =
            unsafe { map_vf_bars(ecam, vf_addr, s2_tables, alloc) }?;
        if !has_bar {
            all_vfs_have_bars = false;
        }
    }
    // Gate: vf_bars_mapped requires at least one BAR per VF.  Report even if
    // the pipeline continues — the DRM driver will fail to access the GPU.
    gate.vf_bars_mapped = all_vfs_have_bars;

    // ── Step 6: Configure SMMU STEs ───────────────────────────────────────────
    for (vf_index, &stream_id) in config.stream_ids.iter().enumerate() {
        unsafe {
            configure_vf_ste(smmu, stream_id, config.vmid, config.s2ttb_pa)?;
        }
        let _ = vf_index; // suppress unused warning
    }

    // ── Step 7: Map ECAM config-space window ──────────────────────────────────
    // Identity-map the PCIe config-space window as DeviceRw.  The Android DRM
    // subsystem reads VF config space (including Vendor ID 0x17CB) through the
    // ECAM window.  Without this mapping the VF is invisible to the guest PCI
    // subsystem even though BARs and STEs are correctly configured.
    unsafe {
        map_ecam_window(config.ecam_window, s2_tables, alloc)?;
    }
    gate.vendor_id_visible = true;

    // ── Step 8: Register VF assignments ──────────────────────────────────────
    for vf_index in 0..AETHER_GPU_NUM_VFS {
        let vf_addr = compute_vf_addr(config.pf_addr, first_vf_offset, vf_stride, vf_index);
        let vf = GpuVirtualFunction {
            addr: vf_addr,
            assigned_guest: GuestId::Android,
            adreno_model: ADRENO_MODEL,
        };
        registry.assign(vf).map_err(GpuSrIovError::from)?;
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Constants ──────────────────────────────────────────────────────────────

    #[test]
    fn qualcomm_vendor_id_value() {
        // PCI-SIG allocation for Qualcomm.
        assert_eq!(QUALCOMM_VENDOR_ID, 0x17CB);
    }

    #[test]
    fn sriov_ext_cap_id_value() {
        // PCIe Base Spec 5.0 Table 9-17.
        assert_eq!(SRIOV_EXT_CAP_ID, 0x0010);
    }

    #[test]
    fn ecap_start_offset_is_0x100() {
        assert_eq!(ECAP_START_OFFSET, 0x100);
    }

    #[test]
    fn sriov_ctrl_vf_enable_is_bit0() {
        assert_eq!(SRIOV_CTRL_VF_ENABLE, 0x0001);
    }

    #[test]
    fn sriov_ctrl_vf_mse_is_bit3() {
        assert_eq!(SRIOV_CTRL_VF_MSE, 0x0008);
    }

    #[test]
    fn combined_ctrl_bits() {
        let ctrl = SRIOV_CTRL_VF_ENABLE | SRIOV_CTRL_VF_MSE;
        assert_eq!(ctrl, 0x0009);
    }

    #[test]
    fn sriov_num_vf_off_is_0x10() {
        // NumVFs at +0x10 per PCIe SR-IOV cap layout (PCIe §9.3.3).
        assert_eq!(SRIOV_NUM_VF_OFF, 0x10);
    }

    #[test]
    fn sriov_total_vf_off_is_0x0e() {
        // TotalVFs (MaxVFs) at +0x0E — distinct from NumVFs at +0x10.
        assert_eq!(SRIOV_TOTAL_VF_OFF, 0x0E);
    }

    #[test]
    fn aether_gpu_num_vfs_is_two() {
        assert_eq!(AETHER_GPU_NUM_VFS, 2);
    }

    // ── GpuSrIovGate ──────────────────────────────────────────────────────────

    #[test]
    fn gate_not_started_both_false() {
        let g = GpuSrIovGate::not_started();
        assert!(!g.vendor_id_visible);
        assert!(!g.vf_bars_mapped);
    }

    #[test]
    fn gate_not_started_does_not_pass() {
        assert!(!GpuSrIovGate::not_started().passes());
    }

    #[test]
    fn gate_vendor_id_only_does_not_pass() {
        let g = GpuSrIovGate { vendor_id_visible: true, vf_bars_mapped: false };
        assert!(!g.passes());
    }

    #[test]
    fn gate_bars_only_does_not_pass() {
        let g = GpuSrIovGate { vendor_id_visible: false, vf_bars_mapped: true };
        assert!(!g.passes());
    }

    #[test]
    fn gate_both_true_passes() {
        let g = GpuSrIovGate { vendor_id_visible: true, vf_bars_mapped: true };
        assert!(g.passes());
    }

    // ── compute_vf_addr ───────────────────────────────────────────────────────

    #[test]
    fn compute_vf0_addr_stride_one() {
        // PF at bus=0, dev=0, fn=0.  FirstVFOffset=1, VFStride=1.
        // VF 0 BDF = 0x0000 + 1 = 0x0001 → bus=0, dev=0, fn=1.
        let pf = PcieAddr::new(0, 0, 0);
        let vf0 = compute_vf_addr(pf, 1, 1, 0);
        assert_eq!(vf0.bus, 0);
        assert_eq!(vf0.device, 0);
        assert_eq!(vf0.function, 1);
    }

    #[test]
    fn compute_vf1_addr_stride_one() {
        // VF 1 BDF = 0x0000 + 1 + 1 × 1 = 0x0002 → bus=0, dev=0, fn=2.
        let pf = PcieAddr::new(0, 0, 0);
        let vf1 = compute_vf_addr(pf, 1, 1, 1);
        assert_eq!(vf1.function, 2);
    }

    #[test]
    fn compute_vf_addr_bus_crossing() {
        // PF at bus=0, dev=31 (0x1F), fn=7. BDF16 = 0x00FF.
        // FirstVFOffset = 1 → VF0 BDF16 = 0x0100 → bus=1, dev=0, fn=0.
        let pf = PcieAddr::new(0, 31, 7);
        let vf0 = compute_vf_addr(pf, 1, 1, 0);
        assert_eq!(vf0.bus, 1);
        assert_eq!(vf0.device, 0);
        assert_eq!(vf0.function, 0);
    }

    #[test]
    fn compute_vf_addr_stride_eight() {
        // PF bus=0, dev=0, fn=0. FirstVFOffset=8, VFStride=8.
        // VF 0: BDF16 = 0 + 8 = 0x0008 → bus=0, dev=1, fn=0.
        // VF 1: BDF16 = 0 + 8 + 8 = 0x0010 → bus=0, dev=2, fn=0.
        let pf = PcieAddr::new(0, 0, 0);
        let vf0 = compute_vf_addr(pf, 8, 8, 0);
        assert_eq!(vf0.device, 1);
        assert_eq!(vf0.function, 0);
        let vf1 = compute_vf_addr(pf, 8, 8, 1);
        assert_eq!(vf1.device, 2);
        assert_eq!(vf1.function, 0);
    }

    #[test]
    fn compute_vf_addr_wrapping() {
        // Verify wrapping arithmetic does not panic.
        let pf = PcieAddr::new(255, 31, 7);
        let _ = compute_vf_addr(pf, 0xFFFF, 0xFFFF, 1);
    }

    // ── GpuSrIovConfig::validate ──────────────────────────────────────────────

    #[test]
    fn config_validate_pf_in_window_ok() {
        let cfg = GpuSrIovConfig {
            pf_addr: PcieAddr::new(0, 2, 0),
            ecam_window: EcamWindow::new(0x2000_0000, 0, 3).unwrap(),
            vmid: 1,
            s2ttb_pa: 0x5000_0000,
            stream_ids: [10, 11],
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn config_validate_pf_outside_window_err() {
        let cfg = GpuSrIovConfig {
            pf_addr: PcieAddr::new(5, 0, 0), // bus 5 outside [0, 3]
            ecam_window: EcamWindow::new(0x2000_0000, 0, 3).unwrap(),
            vmid: 1,
            s2ttb_pa: 0x5000_0000,
            stream_ids: [10, 11],
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_validate_pf_on_end_bus_ok() {
        let cfg = GpuSrIovConfig {
            pf_addr: PcieAddr::new(3, 0, 0),
            ecam_window: EcamWindow::new(0x2000_0000, 0, 3).unwrap(),
            vmid: 1,
            s2ttb_pa: 0x5000_0000,
            stream_ids: [0, 1],
        };
        assert!(cfg.validate().is_ok());
    }

    // ── GpuSrIovError ─────────────────────────────────────────────────────────

    #[test]
    fn error_variants_distinct() {
        assert_ne!(GpuSrIovError::SrIovCapNotFound, GpuSrIovError::NoVfBarsFound);
        assert_ne!(GpuSrIovError::StreamIdOutOfRange, GpuSrIovError::SrIovCapNotFound);
    }

    #[test]
    fn error_insufficient_vfs_carries_max() {
        let e = GpuSrIovError::InsufficientVfs { max_vfs: 1 };
        match e {
            GpuSrIovError::InsufficientVfs { max_vfs } => assert_eq!(max_vfs, 1),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn error_from_gpu_error() {
        let e: GpuSrIovError = GpuError::SrIovNotSupported.into();
        assert!(matches!(e, GpuSrIovError::RegistryError(GpuError::SrIovNotSupported)));
    }

    #[test]
    fn error_from_assignment_error() {
        let e: GpuSrIovError = AssignmentError::InvalidBusRange.into();
        assert!(matches!(e, GpuSrIovError::MapFailed(AssignmentError::InvalidBusRange)));
    }

    // ── SRIOV_CTRL offsets match/cross-check with TOTAL_VF / NUM_VF ──────────

    #[test]
    fn total_vf_and_num_vf_are_distinct_offsets() {
        // MaxVFs is at +0x0E, NumVFs is at +0x10.  They must not be confused.
        assert_ne!(SRIOV_TOTAL_VF_OFF, SRIOV_NUM_VF_OFF);
        assert_eq!(SRIOV_NUM_VF_OFF - SRIOV_TOTAL_VF_OFF, 2);
    }

    #[test]
    fn first_vf_offset_and_stride_offsets() {
        assert_eq!(SRIOV_FIRST_VF_OFFSET_OFF, 0x14);
        assert_eq!(SRIOV_VF_STRIDE_OFF, 0x16);
    }

    // ── ADRENO_MODEL ──────────────────────────────────────────────────────────

    #[test]
    fn adreno_model_is_nonempty() {
        assert!(!ADRENO_MODEL.is_empty());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Compile-time assertions
// ─────────────────────────────────────────────────────────────────────────────

const _: () = {
    use core::mem::size_of;

    // Qualcomm PCI Vendor ID must be the PCI-SIG-assigned value.
    assert!(QUALCOMM_VENDOR_ID == 0x17CB, "Qualcomm Vendor ID must be 0x17CB");

    // SR-IOV Extended Cap ID must match PCIe Base Spec 5.0 Table 9-17.
    assert!(SRIOV_EXT_CAP_ID == 0x0010, "SR-IOV Extended Cap ID must be 0x0010");

    // NumVFs at +0x10 is two bytes past TotalVFs at +0x0E.
    assert!(SRIOV_NUM_VF_OFF == SRIOV_TOTAL_VF_OFF + 2, "NumVFs must be 2 bytes past TotalVFs");

    // VF Enable is bit 0, VF MSE is bit 3 of SRIOV_CTRL.
    assert!(SRIOV_CTRL_VF_ENABLE == 1, "VF Enable must be bit 0");
    assert!(SRIOV_CTRL_VF_MSE == 8, "VF MSE must be bit 3");

    // AETHER enables exactly 2 VFs.
    assert!(AETHER_GPU_NUM_VFS == 2, "AETHER must enable exactly 2 GPU VFs");

    // Gate must be small enough for stack use.
    assert!(size_of::<GpuSrIovGate>() <= 8, "GpuSrIovGate must be ≤ 8 bytes");

    // Config must be stack-allocable in early boot.
    assert!(size_of::<GpuSrIovConfig>() <= 512, "GpuSrIovConfig must be ≤ 512 bytes");
};
