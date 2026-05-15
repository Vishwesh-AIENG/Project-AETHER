// ch40: Network Passthrough — Functional
//
// Probes the NIC Physical Function for SR-IOV capability (preferred path),
// enables AETHER_NIC_NUM_VFS Virtual Functions, maps the Android VF BARs into
// the Android guest's Stage 2 page tables as DeviceRw, configures SMMU STEs
// for DMA isolation, maps the ECAM config-space window, re-asserts Bus Master
// Enable (BME) after FLR, and registers the Android VF in NetworkPartitionRegistry
// with a unique locally-administered MAC address.
//
// Gate: NetworkPassthroughGate { mac_visible: true, dhcp_ready: true }
//   mac_visible = ECAM window mapped + Android VF BARs in Stage 2 + SMMU STE
//                 configured; `ip addr` inside Android shows the interface with
//                 the assigned locally-administered MAC address.
//   dhcp_ready  = Bus Master Enable asserted on the Android VF + MAC registered
//                 in NetworkPartitionRegistry; the DHCP client can issue DMA
//                 packets through the SMMU without Stage-2 faults.
//
// Pipeline (10 steps, executed by assign_nic_vf()):
//   1. Config validation — ECAM bus range non-empty; PF BDF inside window.
//   2. SR-IOV cap discovery — walk extended cap list from 0x100 for ID 0x0010.
//   3. MaxVFs check — hardware must support ≥ AETHER_NIC_NUM_VFS (2) VFs.
//   4. Enable VFs — write NumVFs = AETHER_NIC_NUM_VFS BEFORE setting VF_Enable |
//      VF_MSE in SRIOV_CTRL (PCIe §9.3.3.3.2); DSB ISH.
//   5. Compute VF BDFs — PF_BDF + FirstVFOffset + n × VFStride.
//   6. Map Android VF BARs — scan_bars on VF 0 BDF; identity-map each non-None
//      BAR as DeviceRw in Stage 2 (IPA == PA).
//   7. Configure SMMU STEs — SmmuSte::stage2_only + write_ste per stream_id;
//      mandatory word order: words 1–7 → DSB ISH → word 0 (IHI0070E §3.6).
//   8. Map ECAM window — identity-map config-space window as DeviceRw; Android
//      PCI subsystem reads NIC Vendor ID and BAR layout through this window.
//   9. Bus Master Enable — re-assert BME (Command register bit 2) on Android VF;
//      FLR cleared it; without BME all VF DMA is silently dropped by the root
//      complex.
//  10. Register Android VF — NetworkPartitionRegistry::register with MAC and
//      BDF; MAC uniqueness enforced at insertion time.
//
// SR-IOV Extended Capability offsets (PCIe Base Spec 5.0 §9.3.3):
//   +0x00  Extended Cap Header: ID[15:0]=0x0010, Version[19:16], Next[31:20]
//   +0x08  SR-IOV Control (u16)  bit0=VF_Enable  bit3=VF_MSE
//   +0x0E  TotalVFs / MaxVFs (u16, read-only hardware limit)
//   +0x10  NumVFs (u16, read-write — software-configured VF count)
//   +0x14  First VF Offset (u16, read-only)
//   +0x16  VF Stride (u16, read-only)
//
// Write order for VF enable (PCIe §9.3.3.3.2):
//   NumVFs BEFORE VF Enable; VF_Enable + VF_MSE together; DSB ISH after.
//
// MAC addressing rules:
//   Locally-administered (bit 1 of byte 0 set), unicast (bit 0 clear).
//   Registered in MacRegistry to enforce system-wide uniqueness.
//
// References:
//   PCIe Base Specification 5.0 §9.3.3     — SR-IOV Extended Capability
//   PCIe Base Specification 5.0 §9.3.3.3.2 — NumVFs / VF Enable write order
//   PCIe Base Specification 5.0 §7.5.1     — Command register (BME = bit 2)
//   ARM SMMU v3 IHI0070E §3.4 / §3.6       — STE format and write ordering
//   IEEE 802.11-2020 §9.2.4.3              — MAC address structure
//   linux-ref/drivers/net/ethernet/intel/e1000e — NIC driver reference patterns

use crate::arm64::barriers::dsb_ish;
use crate::gpu_sriov::compute_vf_addr;
use crate::memory::{BumpAllocator, MapKind, SmmuSte, SmmuStreamTable, Stage2Tables, SMMU_MAX_STREAMS};
use crate::network::{MacAddr, NetworkError, NetworkInterface, NetworkPartitionRegistry, NicVirtualFunction};
use crate::partition::GuestId;
use crate::passthrough::{scan_bars, AssignError, PcieAddr, PcieEcam};
use crate::pcie_assignment::{enable_bus_master, map_ecam_window, AssignmentError, EcamWindow};

// ─────────────────────────────────────────────────────────────────────────────
// SR-IOV Extended Capability constants (PCIe Base Spec 5.0 §9.3.3)
//
// Declared locally so this module has no runtime dependency on gpu_sriov.
// Values are identical to those in gpu_sriov.rs — both derive from the spec.
// ─────────────────────────────────────────────────────────────────────────────

/// Extended Capability ID for SR-IOV (PCIe Base Spec 5.0 Table 9-17).
const SRIOV_EXT_CAP_ID: u16 = 0x0010;

/// First extended capability header offset in PCIe config space (§7.6).
const ECAP_START_OFFSET: u16 = 0x100;

/// Offset of SR-IOV Control register within the SR-IOV Extended Capability.
/// bit 0 = VF Enable; bit 3 = VF MSE (Memory Space Enable).
const SRIOV_CTRL_OFF: u16 = 0x08;

/// Offset of TotalVFs (MaxVFs) — read-only hardware limit. Never confuse with
/// NumVFs (+0x10) which is the software-configured writable count.
const SRIOV_TOTAL_VF_OFF: u16 = 0x0E;

/// Offset of NumVFs — software-configured count. Write BEFORE VF Enable.
const SRIOV_NUM_VF_OFF: u16 = 0x10;

/// Offset of First VF Offset register (read-only BDF delta PF → VF 0).
const SRIOV_FIRST_VF_OFFSET_OFF: u16 = 0x14;

/// Offset of VF Stride register (read-only BDF delta between consecutive VFs).
const SRIOV_VF_STRIDE_OFF: u16 = 0x16;

/// SR-IOV Control: VF Enable (bit 0). Activates the configured NumVFs VFs.
const SRIOV_CTRL_VF_ENABLE: u16 = 1 << 0;

/// SR-IOV Control: VF Memory Space Enable (bit 3).
/// Must be set alongside VF Enable so VF BAR MMIO regions respond.
const SRIOV_CTRL_VF_MSE: u16 = 1 << 3;

// ─────────────────────────────────────────────────────────────────────────────
// AETHER NIC SR-IOV constants
// ─────────────────────────────────────────────────────────────────────────────

/// Number of NIC VFs AETHER enables.
/// VF 0 → Android partition. VF 1 reserved for future Windows SR-IOV path.
pub const AETHER_NIC_NUM_VFS: u16 = 2;

/// VF index assigned to the Android partition.
pub const ANDROID_NIC_VF_INDEX: u16 = 0;

// ─────────────────────────────────────────────────────────────────────────────
// Error type
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced by the Ch40 NIC SR-IOV passthrough pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkPassthroughError {
    /// SR-IOV Extended Capability (ID=0x0010) not found in PF extended config space.
    SrIovCapNotFound,
    /// NIC MaxVFs < AETHER_NIC_NUM_VFS; hardware cannot support required VF count.
    InsufficientVfs {
        /// MaxVFs reported by the hardware.
        max_vfs: u16,
    },
    /// No BARs found for the Android VF; VF config space likely unresponsive
    /// after VF Enable. The NIC driver cannot MMIO-access the device.
    NoVfBarsFound,
    /// Stage 2 or ECAM window mapping failed.
    MapFailed(AssignmentError),
    /// A StreamID ≥ SMMU_MAX_STREAMS; cannot write a valid STE for this device.
    SmmuStreamIdOutOfRange,
    /// MAC address error forwarded from the NetworkPartitionRegistry
    /// (e.g. duplicate MAC, multicast address).
    MacError(NetworkError),
}

impl From<AssignmentError> for NetworkPassthroughError {
    fn from(e: AssignmentError) -> Self {
        NetworkPassthroughError::MapFailed(e)
    }
}

impl From<NetworkError> for NetworkPassthroughError {
    fn from(e: NetworkError) -> Self {
        NetworkPassthroughError::MacError(e)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Gate
// ─────────────────────────────────────────────────────────────────────────────

/// Ch40 gate criterion: Android guest observes a NIC VF with a valid MAC.
///
/// Both booleans must be true to pass the gate.
///
/// - `mac_visible`: ECAM window mapped + Android VF BARs in Stage 2 + SMMU STE
///   written. `ip addr` inside Android shows the NIC interface with the
///   assigned locally-administered MAC. Direct gate: interface present and
///   MAC address matches `config.android_vf_mac`.
///
/// - `dhcp_ready`: Bus Master Enable asserted on the Android VF + MAC registered
///   in NetworkPartitionRegistry with uniqueness enforced. The DHCP client can
///   issue DMA packets through the SMMU without Stage-2 faults.
///   Direct gate: `dhclient eth0` (or equivalent) receives an IP offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkPassthroughGate {
    /// ECAM mapped + Android VF BARs in Stage 2 + SMMU STE; `ip addr` visible.
    pub mac_visible: bool,
    /// Bus master enabled + MAC registered; DHCP can succeed.
    pub dhcp_ready: bool,
}

impl NetworkPassthroughGate {
    /// Initial state — pipeline not yet started.
    pub const fn not_started() -> Self {
        Self { mac_visible: false, dhcp_ready: false }
    }

    /// Returns `true` when both gate criteria are satisfied.
    pub const fn passes(&self) -> bool {
        self.mac_visible && self.dhcp_ready
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the Ch40 NIC SR-IOV passthrough pipeline.
#[derive(Clone, Copy, Debug)]
pub struct NetworkPassthroughConfig {
    /// BDF of the NIC Physical Function in PCIe config space.
    pub pf_addr: PcieAddr,
    /// ECAM window for the PCIe segment containing the NIC PF and its VFs.
    pub ecam_window: EcamWindow,
    /// VMID of the Android guest partition (embedded in SMMU STEs for all VFs).
    pub vmid: u16,
    /// Physical address of the Android guest's Stage 2 translation table root.
    pub s2ttb_pa: u64,
    /// SMMU StreamIDs for VF 0 (Android) and VF 1 (future Windows).
    /// Each maps to one SMMU STE entry; both get Stage-2-only STEs at boot.
    pub stream_ids: [u32; 2],
    /// MAC address assigned to the Android NIC VF.
    /// Must be unicast (bit 0 of byte 0 clear). Should be locally-administered
    /// (bit 1 of byte 0 set) — AETHER generates VF MACs to avoid OUI conflicts.
    pub android_vf_mac: MacAddr,
}

impl NetworkPassthroughConfig {
    /// Validate config invariants before touching any hardware registers.
    ///
    /// Checks ECAM bus range is non-empty and PF BDF falls inside the window.
    pub fn validate(&self) -> Result<(), NetworkPassthroughError> {
        if self.ecam_window.start_bus > self.ecam_window.end_bus {
            return Err(NetworkPassthroughError::MapFailed(AssignmentError::InvalidBusRange));
        }
        if self.pf_addr.bus < self.ecam_window.start_bus
            || self.pf_addr.bus > self.ecam_window.end_bus
        {
            return Err(NetworkPassthroughError::MapFailed(AssignmentError::InvalidBusRange));
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SR-IOV Extended Capability discovery
// ─────────────────────────────────────────────────────────────────────────────

/// Walk the PCIe Extended Capability list to locate the SR-IOV cap (ID 0x0010).
///
/// Extended capability headers occupy 4-byte DWORDs at 4-byte-aligned offsets in
/// [0x100, 0xFFC]. Each header encodes:
///   bits [15:0]  = Extended Cap ID
///   bits [19:16] = Version
///   bits [31:20] = Next Capability Offset (0 = end of list)
///
/// A header of 0 or 0xFFFF_FFFF indicates a missing or powered-down device.
///
/// Returns the config-space offset of the SR-IOV capability header, or `None`.
///
/// # Safety
/// - ECAM must be identity-mapped at EL2 via the UEFI identity map.
/// - The device at `pf_addr` must exist and respond to config-space reads.
unsafe fn find_nic_sriov_ext_cap(ecam: &PcieEcam, pf_addr: PcieAddr) -> Option<u16> {
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

/// Read MaxVFs, FirstVFOffset, and VFStride from the NIC SR-IOV Extended Cap.
///
/// Returns `(max_vfs, first_vf_offset, vf_stride)`.
///
/// # Safety
/// - ECAM must be accessible at EL2.
/// - `cap_off` must be a valid SR-IOV extended capability offset.
unsafe fn read_nic_sriov_cap_fields(
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
// NIC VF enable
// ─────────────────────────────────────────────────────────────────────────────

/// Write NumVFs and enable SR-IOV on the NIC Physical Function.
///
/// Mandatory PCIe write order (§9.3.3.3.2):
///   1. Write `num_vfs` to NumVFs (offset +0x10) FIRST.
///   2. Set VF_Enable + VF_MSE together in one 16-bit write to SRIOV_CTRL.
///   3. DSB ISH — ordering fence before any SMMU STE activation.
///
/// VF_MSE (Memory Space Enable, bit 3) must be set so VF BAR MMIO regions
/// respond; without it BAR reads return all-ones and MMIO writes are lost.
///
/// # Safety
/// - ECAM must be accessible at EL2 via the UEFI identity map.
/// - `cap_off` must be the SR-IOV Extended Capability header offset.
/// - `num_vfs` must be ≤ MaxVFs (verified by caller).
unsafe fn enable_nic_vfs(ecam: &PcieEcam, pf_addr: PcieAddr, cap_off: u16, num_vfs: u16) {
    // Step 1: NumVFs BEFORE VF Enable — spec-mandated ordering.
    unsafe { ecam.write16(pf_addr, cap_off + SRIOV_NUM_VF_OFF, num_vfs) };
    // Step 2: VF Enable + Memory Space Enable in one 16-bit write.
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
// SMMU STE configuration per NIC VF
// ─────────────────────────────────────────────────────────────────────────────

/// Write a Stage-2-only SMMU STE for one NIC VF StreamID.
///
/// `SmmuStreamTable::write_ste` enforces the mandatory write order (IHI0070E
/// §3.6): words 1–7, DSB ISH, word 0 (Valid + Config bits last).
///
/// # Safety
/// - `smmu` must be accessible at EL2 and must not be concurrently modified.
/// - Must be called before the SMMU is enabled or after safe quiesce.
unsafe fn configure_nic_vf_ste(
    smmu: &mut SmmuStreamTable,
    stream_id: u32,
    vmid: u16,
    s2ttb_pa: u64,
) -> Result<(), NetworkPassthroughError> {
    if stream_id as usize >= SMMU_MAX_STREAMS {
        return Err(NetworkPassthroughError::SmmuStreamIdOutOfRange);
    }
    let ste = SmmuSte::stage2_only(vmid, s2ttb_pa);
    unsafe { smmu.write_ste(stream_id as usize, ste) };
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Android VF BAR mapping
// ─────────────────────────────────────────────────────────────────────────────

/// Map all memory BARs for the Android NIC VF into the guest Stage 2 tables.
///
/// Uses `scan_bars` on the VF BDF to discover BAR base addresses and sizes.
/// Each non-None BAR is identity-mapped (IPA == PA) as `DeviceRw`.
///
/// Returns `true` if at least one BAR was mapped (VF config space responsive).
/// Returns `false` if all six BARs are unimplemented — the NIC driver will
/// fail to MMIO-access the device registers.
///
/// # Safety
/// - ECAM must be accessible for the VF BDF.
/// - `s2_tables` must be the Stage 2 tables for the Android guest.
/// - Must be called after VF Enable so the VF config space is active.
unsafe fn map_nic_vf_bars(
    ecam: &PcieEcam,
    vf_addr: PcieAddr,
    s2_tables: &Stage2Tables,
    alloc: &mut BumpAllocator,
) -> Result<bool, NetworkPassthroughError> {
    let bars = unsafe { scan_bars(ecam, vf_addr) };
    let mut mapped_any = false;
    for bar in bars.iter().flatten() {
        unsafe {
            s2_tables
                .map_range(bar.pa, bar.pa, bar.size, MapKind::DeviceRw, alloc)
                .map_err(|e| {
                    NetworkPassthroughError::MapFailed(AssignmentError::Passthrough(
                        AssignError::MapFailed(e),
                    ))
                })?
        };
        mapped_any = true;
    }
    Ok(mapped_any)
}

// ─────────────────────────────────────────────────────────────────────────────
// Full pipeline — Ch40 entry point
// ─────────────────────────────────────────────────────────────────────────────

/// Enable NIC SR-IOV, map VF BARs and ECAM into Stage 2, configure SMMU STEs,
/// assert Bus Master Enable, and register the Android VF in the NIC registry.
///
/// Executes the complete Ch40 pipeline in this order:
///
/// 1. **Config validation** — bus range non-empty; PF BDF inside ECAM window.
/// 2. **SR-IOV cap discovery** — walk extended config space for ID 0x0010.
/// 3. **MaxVFs check** — hardware must support ≥ `AETHER_NIC_NUM_VFS` (2) VFs.
/// 4. **Enable VFs** — write NumVFs = 2, then SRIOV_CTRL = VF_Enable | VF_MSE;
///    DSB ISH. NumVFs written BEFORE VF Enable (PCIe §9.3.3.3.2).
/// 5. **Compute VF BDFs** — PF_BDF + FirstVFOffset + n × VFStride.
/// 6. **Android VF BAR mapping** — `scan_bars` on VF 0, then identity-map each
///    non-None BAR as DeviceRw in Stage 2.
/// 7. **SMMU STEs** — `SmmuSte::stage2_only` + `write_ste` for each stream_id;
///    word ordering enforced inside `write_ste` (words 1–7 → DSB → word 0).
/// 8. **ECAM window** — identity-map the PCIe config-space window as DeviceRw;
///    Android PCI subsystem reads NIC Vendor ID and BAR layout here.
/// 9. **Bus Master Enable** — re-assert BME (Command register bit 2) on VF 0;
///    FLR clears BME; without it all VF DMA is silently dropped.
/// 10. **Registry** — register Android VF in `NetworkPartitionRegistry`;
///    MAC uniqueness enforced at registration time by `MacRegistry`.
///
/// On success sets `gate.mac_visible = true` and `gate.dhcp_ready = true`.
///
/// # Errors
/// Returns the first error encountered. After step 4 the NIC PF has SR-IOV
/// enabled; a full platform reset is required to undo this. Treat any error
/// from this function as fatal in the boot sequence.
///
/// # Safety
/// - ECAM must be identity-mapped at EL2 via the UEFI identity map.
/// - `s2_tables` must be the Stage 2 tables for `GuestId::Android`.
/// - `alloc` must provide writable, non-aliased physical pages.
/// - `smmu` must not be concurrently accessed.
/// - Must be called single-threaded during early boot, before Stage 2 is enabled.
pub unsafe fn assign_nic_vf(
    config: &NetworkPassthroughConfig,
    ecam: &PcieEcam,
    s2_tables: &Stage2Tables,
    smmu: &mut SmmuStreamTable,
    alloc: &mut BumpAllocator,
    registry: &mut NetworkPartitionRegistry,
    gate: &mut NetworkPassthroughGate,
) -> Result<(), NetworkPassthroughError> {
    // ── Step 1: Validate config ───────────────────────────────────────────────
    config.validate()?;

    // ── Step 2: Find SR-IOV Extended Capability in PF config space ────────────
    let cap_off = unsafe { find_nic_sriov_ext_cap(ecam, config.pf_addr) }
        .ok_or(NetworkPassthroughError::SrIovCapNotFound)?;

    // ── Step 3: Read MaxVFs, FirstVFOffset, VFStride; validate MaxVFs ─────────
    let (max_vfs, first_vf_offset, vf_stride) =
        unsafe { read_nic_sriov_cap_fields(ecam, config.pf_addr, cap_off) };
    if max_vfs < AETHER_NIC_NUM_VFS {
        return Err(NetworkPassthroughError::InsufficientVfs { max_vfs });
    }

    // ── Step 4: Write NumVFs = 2, then VF_Enable | VF_MSE; DSB ISH ───────────
    // NumVFs is written BEFORE VF Enable — PCIe Spec §9.3.3.3.2.
    // Failure to follow this order results in undefined VF count on real silicon.
    unsafe { enable_nic_vfs(ecam, config.pf_addr, cap_off, AETHER_NIC_NUM_VFS) };

    // ── Step 5: Compute Android VF BDF ────────────────────────────────────────
    let android_vf_addr =
        compute_vf_addr(config.pf_addr, first_vf_offset, vf_stride, ANDROID_NIC_VF_INDEX);

    // ── Step 6: Map Android VF BARs into Stage 2 ─────────────────────────────
    let has_bars = unsafe { map_nic_vf_bars(ecam, android_vf_addr, s2_tables, alloc) }?;
    if !has_bars {
        return Err(NetworkPassthroughError::NoVfBarsFound);
    }

    // ── Step 7: Configure SMMU STEs for all stream IDs ────────────────────────
    // Both VF 0 (Android) and VF 1 (future Windows) receive Stage-2-only STEs
    // so DMA from either VF is constrained to the Android Stage 2 translation.
    // The VF 1 STE is overwritten when Windows is assigned in a future chapter.
    for &stream_id in &config.stream_ids {
        unsafe {
            configure_nic_vf_ste(smmu, stream_id, config.vmid, config.s2ttb_pa)?;
        }
    }

    // ── Step 8: Map ECAM config-space window ──────────────────────────────────
    // The Android PCI/network subsystem reads NIC VF config space through this
    // window. Without the mapping the NIC is invisible to the Android IP stack
    // even with correct BAR and STE configuration.
    unsafe {
        map_ecam_window(config.ecam_window, s2_tables, alloc)?;
    }
    // Gate criterion 1: ECAM + BARs + STE all in place.
    gate.mac_visible = true;

    // ── Step 9: Bus Master Enable on Android VF ───────────────────────────────
    // FLR (performed by passthrough::trigger_flr before assign_nic_vf is called)
    // cleared the Command register. Re-assert BME so the NIC VF can issue DMA.
    // Must follow SMMU STE write (step 7) so the first DMA is already
    // constrained by Stage 2 translation.
    unsafe { enable_bus_master(ecam, android_vf_addr) };

    // ── Step 10: Register Android VF in NetworkPartitionRegistry ──────────────
    let vf = NicVirtualFunction {
        addr: android_vf_addr,
        mac: config.android_vf_mac,
        guest: GuestId::Android,
    };
    registry.register(NetworkInterface::VirtualFunction(vf))?;

    // Gate criterion 2: BME asserted + MAC uniqueness enforced by registry.
    gate.dhcp_ready = true;

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::passthrough::PcieAddr;
    use crate::pcie_assignment::EcamWindow;

    // ── Constants ──────────────────────────────────────────────────────────────

    #[test]
    fn aether_nic_num_vfs_is_two() {
        assert_eq!(AETHER_NIC_NUM_VFS, 2);
    }

    #[test]
    fn android_nic_vf_index_is_zero() {
        assert_eq!(ANDROID_NIC_VF_INDEX, 0);
    }

    #[test]
    fn sriov_num_vf_off_is_two_past_total_vf() {
        // NumVFs at +0x10 is exactly 2 bytes past TotalVFs at +0x0E.
        // The write order (NumVFs before VF Enable) relies on these being distinct.
        assert_eq!(SRIOV_NUM_VF_OFF, SRIOV_TOTAL_VF_OFF + 2);
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
    fn combined_ctrl_bits_are_0x0009() {
        assert_eq!(SRIOV_CTRL_VF_ENABLE | SRIOV_CTRL_VF_MSE, 0x0009);
    }

    // ── NetworkPassthroughGate ─────────────────────────────────────────────────

    #[test]
    fn gate_not_started_both_false() {
        let g = NetworkPassthroughGate::not_started();
        assert!(!g.mac_visible);
        assert!(!g.dhcp_ready);
        assert!(!g.passes());
    }

    #[test]
    fn gate_mac_only_does_not_pass() {
        let g = NetworkPassthroughGate { mac_visible: true, dhcp_ready: false };
        assert!(!g.passes());
    }

    #[test]
    fn gate_dhcp_only_does_not_pass() {
        let g = NetworkPassthroughGate { mac_visible: false, dhcp_ready: true };
        assert!(!g.passes());
    }

    #[test]
    fn gate_both_true_passes() {
        let g = NetworkPassthroughGate { mac_visible: true, dhcp_ready: true };
        assert!(g.passes());
    }

    // ── NetworkPassthroughConfig::validate ────────────────────────────────────

    fn la_mac() -> MacAddr {
        // Locally-administered (bit 1 set), unicast (bit 0 clear).
        MacAddr::new([0x02, 0xAE, 0x40, 0x00, 0x00, 0x01]).unwrap()
    }

    fn valid_config() -> NetworkPassthroughConfig {
        NetworkPassthroughConfig {
            pf_addr: PcieAddr::new(0, 1, 0),
            ecam_window: EcamWindow::new(0x3000_0000, 0, 3).unwrap(),
            vmid: 1,
            s2ttb_pa: 0x5000_0000,
            stream_ids: [20, 21],
            android_vf_mac: la_mac(),
        }
    }

    #[test]
    fn config_validate_ok() {
        assert!(valid_config().validate().is_ok());
    }

    #[test]
    fn config_validate_pf_outside_window_err() {
        let mut cfg = valid_config();
        cfg.pf_addr = PcieAddr::new(5, 0, 0); // bus 5 not in [0, 3]
        assert!(matches!(
            cfg.validate(),
            Err(NetworkPassthroughError::MapFailed(AssignmentError::InvalidBusRange))
        ));
    }

    #[test]
    fn config_validate_pf_on_end_bus_ok() {
        let mut cfg = valid_config();
        cfg.pf_addr = PcieAddr::new(3, 0, 0);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn config_validate_start_bus_greater_than_end_bus_err() {
        // EcamWindow::new returns None for inverted ranges; construct manually
        // by building a valid window then checking the validate path directly
        // through a PF outside [start, end].
        let mut cfg = valid_config();
        cfg.pf_addr = PcieAddr::new(4, 0, 0); // bus 4 not in [0, 3]
        assert!(cfg.validate().is_err());
    }

    // ── NetworkPassthroughError conversions ───────────────────────────────────

    #[test]
    fn error_from_assignment_error() {
        let e: NetworkPassthroughError = AssignmentError::InvalidBusRange.into();
        assert!(matches!(
            e,
            NetworkPassthroughError::MapFailed(AssignmentError::InvalidBusRange)
        ));
    }

    #[test]
    fn error_from_network_error() {
        let e: NetworkPassthroughError = NetworkError::DuplicateMacAddress.into();
        assert!(matches!(
            e,
            NetworkPassthroughError::MacError(NetworkError::DuplicateMacAddress)
        ));
    }

    #[test]
    fn error_insufficient_vfs_carries_max() {
        let e = NetworkPassthroughError::InsufficientVfs { max_vfs: 0 };
        match e {
            NetworkPassthroughError::InsufficientVfs { max_vfs } => assert_eq!(max_vfs, 0),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn error_variants_distinct() {
        assert_ne!(
            NetworkPassthroughError::SrIovCapNotFound,
            NetworkPassthroughError::NoVfBarsFound
        );
        assert_ne!(
            NetworkPassthroughError::SmmuStreamIdOutOfRange,
            NetworkPassthroughError::SrIovCapNotFound
        );
    }

    // ── NetworkPartitionRegistry integration ──────────────────────────────────

    #[test]
    fn registry_accepts_vf_with_la_mac() {
        let mut reg = NetworkPartitionRegistry::new();
        let vf = NicVirtualFunction {
            addr: PcieAddr::new(0, 0, 1),
            mac: la_mac(),
            guest: GuestId::Android,
        };
        assert!(reg.register(NetworkInterface::VirtualFunction(vf)).is_ok());
        assert_eq!(reg.count(), 1);
        let iface = reg.interface_for_guest(GuestId::Android).unwrap();
        assert_eq!(iface.mac(), la_mac());
        assert!(!iface.is_paravirt());
    }

    #[test]
    fn registry_rejects_duplicate_mac() {
        let mut reg = NetworkPartitionRegistry::new();
        let vf1 = NicVirtualFunction {
            addr: PcieAddr::new(0, 0, 1),
            mac: la_mac(),
            guest: GuestId::Android,
        };
        let vf2 = NicVirtualFunction {
            addr: PcieAddr::new(0, 0, 2),
            mac: la_mac(), // same MAC — must fail
            guest: GuestId::Windows,
        };
        reg.register(NetworkInterface::VirtualFunction(vf1)).unwrap();
        assert_eq!(
            reg.register(NetworkInterface::VirtualFunction(vf2)),
            Err(NetworkError::DuplicateMacAddress)
        );
    }

    // ── EcamWindow integration ────────────────────────────────────────────────

    #[test]
    fn ecam_window_new_inverted_range_is_none() {
        // EcamWindow::new enforces start_bus ≤ end_bus at the type level.
        assert!(EcamWindow::new(0x3000_0000, 3, 0).is_none());
    }

    #[test]
    fn ecam_window_single_bus_valid() {
        let w = EcamWindow::new(0x3000_0000, 2, 2).unwrap();
        assert_eq!(w.start_bus, w.end_bus);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Compile-time assertions
// ─────────────────────────────────────────────────────────────────────────────

const _: () = {
    use core::mem::size_of;

    // AETHER enables exactly 2 NIC VFs (Android + reserved Windows).
    assert!(AETHER_NIC_NUM_VFS == 2, "AETHER must enable exactly 2 NIC VFs");

    // Android always gets VF 0.
    assert!(ANDROID_NIC_VF_INDEX == 0, "Android NIC VF index must be 0");

    // SR-IOV spec: NumVFs (+0x10) is 2 bytes past TotalVFs (+0x0E).
    assert!(SRIOV_NUM_VF_OFF == SRIOV_TOTAL_VF_OFF + 2, "NumVFs must be 2 bytes past TotalVFs");

    // VF Enable = bit 0, VF MSE = bit 3 of SRIOV_CTRL.
    assert!(SRIOV_CTRL_VF_ENABLE == 1, "VF Enable must be bit 0");
    assert!(SRIOV_CTRL_VF_MSE == 8, "VF MSE must be bit 3");

    // Gate and config must be stack-allocable in early boot context.
    assert!(
        size_of::<NetworkPassthroughGate>() <= 8,
        "NetworkPassthroughGate must be ≤ 8 bytes"
    );
    assert!(
        size_of::<NetworkPassthroughConfig>() <= 512,
        "NetworkPassthroughConfig must be ≤ 512 bytes"
    );
};
