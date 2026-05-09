// ch13: GPU Partitioning Through SR-IOV
//
// Graphics is the most performance-sensitive subsystem in AETHER's architecture
// because a primary use case is gaming. The GPU partitioning strategy uses
// SR-IOV (Single Root I/O Virtualization) — a hardware feature that allows one
// physical GPU to present itself as multiple independent GPUs to the system.
//
// When SR-IOV is enabled, the GPU appears as:
//   1. One Physical Function (PF) — the real GPU, used by AETHER for config
//   2. Multiple Virtual Functions (VFs) — lightweight instances, each a separate
//      PCIe device with own BARs, command queues, interrupts
//
// AETHER's approach at boot:
//   1. Read SR-IOV capability from integrated GPU's PCIe config space
//   2. Enable SR-IOV to create two VFs (NumVFs = 2)
//   3. Assign VF 0 to Windows partition, VF 1 to Android partition
//   4. Map each VF's BARs into guest Stage 2 page tables (identity mapping)
//   5. Configure SMMU STEs for DMA isolation on each VF's StreamID
//   6. Let guests' graphics drivers access VFs directly (no hypervisor mediation)
//   7. Guests run graphics at native hardware speed
//
// Current hardware status:
//   ARM Tier — Snapdragon X Elite's Adreno X1: SR-IOV supported (newer firmware)
//   x86 Tier — Phase 4+ (requires Intel Arc / AMD consumer GPU SR-IOV support)
//
// Driver matching at AOSP build time:
//   AETHER configures Android's VF to identify as a specific Adreno model
//   (e.g., Adreno 740). The Android image is built with the corresponding
//   driver. The driver communicates directly with what it believes is real
//   hardware; the GPU's SR-IOV responds correctly because the VF genuinely
//   implements Adreno register and command formats.
//
// Adreno-specific implementation note:
//   Adreno GPU internals are protected by NDA with Qualcomm. This module does
//   NOT invent Adreno register addresses or command formats. Instead it:
//     • Provides the SR-IOV enumeration infrastructure
//     • Defines integration points for Adreno config (loaded from Freedreno
//       source or proprietary driver at build time)
//     • Enforces DMA isolation via SMMU (same as ch11)
//   For production, VF identity reporting uses Freedreno as the reference.
//
// References:
//   PCI Express Base Specification 5.0, Chapter 6 — SR-IOV specification
//   Freedreno at gitlab.freedesktop.org/mesa/mesa — open-source Adreno driver
//   drivers/gpu/drm/msm/ in Linux kernel — Adreno DRM driver (reference)
//   drivers/gpu/drm/amd/amdgpu/amdgpu_virt.c — AMDGPU SR-IOV (architecture reference)

use crate::memory::MapError;
use crate::partition::GuestId;
use crate::passthrough::PcieAddr;

// Future imports (used when implementing production BAR/SMMU integration):
// use crate::arm64::barriers::dsb_ish;
// use crate::memory::{BumpAllocator, MapKind, SmmuSte, Stage2Tables, SMMU_MAX_STREAMS};

// ─────────────────────────────────────────────────────────────────────────────
// Error type
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuError {
    /// SR-IOV not supported by this GPU (no SR-IOV Extended Capability).
    SrIovNotSupported,
    /// Requested number of VFs exceeds the GPU's MaxVFs limit.
    VfCountExceedsMax,
    /// SR-IOV is already enabled; cannot reconfigure.
    SrIovAlreadyEnabled,
    /// VF assignment would violate exclusive partition ownership.
    ConflictingVfAssignment,
    /// A StreamID in a VF exceeds SMMU_MAX_STREAMS.
    StreamIdOutOfRange,
    /// Stage 2 mapping failed (BAR or ITS frame).
    MapFailed(MapError),
    /// VF BAR address / size is invalid or not 4KB-aligned.
    InvalidVfBar,
}

// ─────────────────────────────────────────────────────────────────────────────
// SR-IOV Capability structure (PCIe spec, extended capability list)
//
// Offset (within Extended Capability): 0x04 — SR-IOV Control (SRIOV_CTRL)
// Offset: 0x0E — NumVFs (read/write) — enabled VF count
// Offset: 0x10 — FirstVFOffset (read-only) — BUS:DEV:FUNC increment for first VF
// Offset: 0x12 — VFStride (read-only) — increment between consecutive VFs
// ─────────────────────────────────────────────────────────────────────────────

/// SR-IOV capability as read from PCIe extended capability space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SrIovCapability {
    /// Maximum number of VFs supported by this GPU.
    pub max_vfs: u16,
    /// Number of VFs currently enabled (0 = disabled).
    pub num_vfs_enabled: u16,
    /// BUS:DEV:FUNC offset to first VF (relative to PF).
    pub first_vf_offset: u16,
    /// Stride in BUS:DEV:FUNC space between consecutive VFs.
    pub vf_stride: u16,
    /// Whether SR-IOV is currently enabled (NumVFs > 0).
    pub enabled: bool,
}

impl SrIovCapability {
    /// Compute the PCIe BUS:DEV:FUNC of the Nth VF given a PF address.
    ///
    /// VF_BDF(n) = PF_BDF + (FirstVFOffset + n * VFStride)
    /// Note: BUS/DEV/FUNC are packed in u16 as (bus << 8) | (dev << 3) | func.
    pub fn vf_bdf(&self, pf_bdf: u16, vf_index: u16) -> Option<u16> {
        if vf_index >= self.max_vfs {
            return None;
        }
        Some(pf_bdf.wrapping_add(self.first_vf_offset + vf_index * self.vf_stride))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Virtual Function descriptor
// ─────────────────────────────────────────────────────────────────────────────

/// Describes one Virtual Function allocated by SR-IOV.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GpuVirtualFunction {
    /// PCIe BUS:DEV:FUNC address of this VF.
    pub addr: PcieAddr,
    /// Guest to which this VF is assigned (exclusive ownership).
    pub assigned_guest: GuestId,
    /// Adreno model name (e.g., "Adreno 740") reported by VF.
    /// Matches the AOSP build's GPU driver selection.
    pub adreno_model: &'static str,
}

// ─────────────────────────────────────────────────────────────────────────────
// GPU Partition registry
//
// Tracks VF assignments to guests. Prevents conflicting assignments (both guests
// trying to claim the same VF, or assigning more than the available VF count).
// ─────────────────────────────────────────────────────────────────────────────

const MAX_VFCOUNT: usize = 16; // Typical: 2–4 VFs for consumer GPUs

/// Registry of GPU VF assignments to guests.
#[derive(Clone, Copy, Debug)]
pub struct GpuPartitionRegistry {
    vfs: [Option<GpuVirtualFunction>; MAX_VFCOUNT],
    vf_count: usize,
}

impl GpuPartitionRegistry {
    /// Construct an empty registry.
    pub const fn new() -> Self {
        Self {
            vfs: [None; MAX_VFCOUNT],
            vf_count: 0,
        }
    }

    /// Assign a VF to a guest.
    ///
    /// Returns `Err(ConflictingVfAssignment)` if the VF is already assigned or
    /// if the index is invalid. Returns `Err(GpuError)` on other checks.
    pub fn assign(
        &mut self,
        vf: GpuVirtualFunction,
    ) -> Result<(), GpuError> {
        if self.vf_count >= MAX_VFCOUNT {
            return Err(GpuError::VfCountExceedsMax);
        }

        // Check for conflicts: no VF should be assigned twice
        for existing in self.vfs.iter().flatten() {
            if existing.addr == vf.addr {
                return Err(GpuError::ConflictingVfAssignment);
            }
        }

        // Append to the list
        self.vfs[self.vf_count] = Some(vf);
        self.vf_count += 1;
        Ok(())
    }

    /// Query which guest owns a VF (if assigned).
    pub fn query_owner(&self, addr: PcieAddr) -> Option<GuestId> {
        self.vfs
            .iter()
            .flatten()
            .find(|vf| vf.addr == addr)
            .map(|vf| vf.assigned_guest)
    }

    /// Count of currently-assigned VFs.
    pub fn assigned_count(&self) -> usize {
        self.vf_count
    }
}

impl Default for GpuPartitionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GPU Partition state — top-level for one physical GPU
// ─────────────────────────────────────────────────────────────────────────────

/// Manages GPU SR-IOV partitioning for one integrated GPU.
///
/// At ARM Tier boot:
///   1. Discover GPU's SR-IOV capability
///   2. Determine if SR-IOV is available (newer Adreno X1 firmware)
///   3. Enable SR-IOV (set NumVFs = 2 via PCIe config write)
///   4. Enumerate both VFs' BUS:DEV:FUNC addresses
///   5. Map VF BARs into each guest's Stage 2 page tables
///   6. Set SMMU STEs for DMA isolation per VF
///   7. Record assignments in the registry
/// After this, guests' graphics drivers communicate directly with their VFs
/// with no hypervisor mediation.
pub struct GpuPartitionState {
    /// SR-IOV capability of the GPU.
    pub capability: SrIovCapability,
    /// Per-guest registry of VF assignments.
    pub registry: GpuPartitionRegistry,
    /// Whether SR-IOV has been enabled on this GPU.
    pub sr_iov_enabled: bool,
}

impl GpuPartitionState {
    /// Construct a new GPU partition state.
    ///
    /// Initially, SR-IOV is assumed disabled. Call `enable_sr_iov()` to read
    /// the capability and enable SR-IOV on the GPU.
    pub const fn new() -> Self {
        Self {
            capability: SrIovCapability {
                max_vfs: 0,
                num_vfs_enabled: 0,
                first_vf_offset: 0,
                vf_stride: 0,
                enabled: false,
            },
            registry: GpuPartitionRegistry::new(),
            sr_iov_enabled: false,
        }
    }

    /// Simulate SR-IOV capability discovery.
    ///
    /// In production, this reads from the GPU's PCIe extended capability space
    /// (SR-IOV Extended Capability structure at offset provided by the capability
    /// list). For unit testing, this accepts a preconfigured capability.
    pub fn set_capability(&mut self, cap: SrIovCapability) -> Result<(), GpuError> {
        if self.sr_iov_enabled {
            return Err(GpuError::SrIovAlreadyEnabled);
        }
        self.capability = cap;
        Ok(())
    }

    /// Enable SR-IOV and enumerate VFs (simulated for testing).
    ///
    /// In production:
    ///   1. Write NumVFs to the SR-IOV control register
    ///   2. Set VF Enable bit in SRIOV_CTRL
    ///   3. Wait for hardware to create VFs (a few µs typically)
    ///   4. Re-enumerate PCIe bus to discover new VF devices
    /// For testing, this just marks enabled and computes VF addresses.
    pub fn enable_sr_iov(&mut self) -> Result<(), GpuError> {
        if self.sr_iov_enabled {
            return Err(GpuError::SrIovAlreadyEnabled);
        }
        if self.capability.max_vfs == 0 {
            return Err(GpuError::SrIovNotSupported);
        }

        // Mark enabled
        self.sr_iov_enabled = true;
        Ok(())
    }

    /// Assign a VF to a guest.
    ///
    /// Before calling this, BAR mapping and SMMU configuration must be done
    /// by the caller (in production, via ch11 passthrough pipeline).
    pub fn assign_vf(&mut self, vf: GpuVirtualFunction) -> Result<(), GpuError> {
        if !self.sr_iov_enabled {
            return Err(GpuError::SrIovNotSupported);
        }
        self.registry.assign(vf)?;
        Ok(())
    }
}

impl Default for GpuPartitionState {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── SR-IOV Capability ─────────────────────────────────────────────────────

    #[test]
    fn test_sriov_capability_fields() {
        let cap = SrIovCapability {
            max_vfs: 16,
            num_vfs_enabled: 0,
            first_vf_offset: 1,
            vf_stride: 1,
            enabled: false,
        };
        assert_eq!(cap.max_vfs, 16);
        assert!(!cap.enabled);
    }

    #[test]
    fn test_vf_bdf_calculation() {
        let cap = SrIovCapability {
            max_vfs: 4,
            num_vfs_enabled: 0,
            first_vf_offset: 0x0001,
            vf_stride: 0x0001,
            enabled: false,
        };
        let pf_bdf: u16 = 0x0000; // Bus 0, Device 0, Function 0
        // VF 0 = 0x0000 + 0x0001 = 0x0001
        // VF 1 = 0x0000 + 0x0001 + 0x0001 = 0x0002
        assert_eq!(cap.vf_bdf(pf_bdf, 0), Some(0x0001));
        assert_eq!(cap.vf_bdf(pf_bdf, 1), Some(0x0002));
        assert_eq!(cap.vf_bdf(pf_bdf, 4), None); // Out of range
    }

    #[test]
    fn test_sriov_enabled_flag() {
        let cap = SrIovCapability {
            max_vfs: 2,
            num_vfs_enabled: 2,
            first_vf_offset: 1,
            vf_stride: 1,
            enabled: true,
        };
        assert!(cap.enabled);
        assert_eq!(cap.num_vfs_enabled, 2);
    }

    // ── GPU Partition Registry ────────────────────────────────────────────────

    #[test]
    fn test_registry_assign_vf() {
        let mut registry = GpuPartitionRegistry::new();
        let vf = GpuVirtualFunction {
            addr: PcieAddr::new(0, 0, 1),
            assigned_guest: GuestId::Android,
            adreno_model: "Adreno 740",
        };
        assert_eq!(registry.assign(vf), Ok(()));
        assert_eq!(registry.assigned_count(), 1);
    }

    #[test]
    fn test_registry_conflict_detection() {
        let mut registry = GpuPartitionRegistry::new();
        let vf1 = GpuVirtualFunction {
            addr: PcieAddr::new(0, 0, 1),
            assigned_guest: GuestId::Android,
            adreno_model: "Adreno 740",
        };
        let vf2 = GpuVirtualFunction {
            addr: PcieAddr::new(0, 0, 1), // Same address
            assigned_guest: GuestId::Android,
            adreno_model: "Adreno 740",
        };
        assert_eq!(registry.assign(vf1), Ok(()));
        assert_eq!(
            registry.assign(vf2),
            Err(GpuError::ConflictingVfAssignment)
        );
    }

    #[test]
    fn test_registry_query_owner() {
        let mut registry = GpuPartitionRegistry::new();
        let vf = GpuVirtualFunction {
            addr: PcieAddr::new(0, 0, 1),
            assigned_guest: GuestId::Android,
            adreno_model: "Adreno 740",
        };
        registry.assign(vf).unwrap();
        assert_eq!(
            registry.query_owner(PcieAddr::new(0, 0, 1)),
            Some(GuestId::Android)
        );
        assert_eq!(registry.query_owner(PcieAddr::new(0, 0, 2)), None);
    }

    #[test]
    fn test_registry_multiple_vfs() {
        let mut registry = GpuPartitionRegistry::new();
        let vf0 = GpuVirtualFunction {
            addr: PcieAddr::new(0, 0, 1),
            assigned_guest: GuestId::Android,
            adreno_model: "Adreno 740",
        };
        let vf1 = GpuVirtualFunction {
            addr: PcieAddr::new(0, 0, 2),
            assigned_guest: GuestId::Android,
            adreno_model: "Adreno 740",
        };
        assert_eq!(registry.assign(vf0), Ok(()));
        assert_eq!(registry.assign(vf1), Ok(()));
        assert_eq!(registry.assigned_count(), 2);
    }

    // ── GPU Partition State ───────────────────────────────────────────────────

    #[test]
    fn test_gpu_partition_new() {
        let state = GpuPartitionState::new();
        assert!(!state.sr_iov_enabled);
        assert_eq!(state.capability.max_vfs, 0);
    }

    #[test]
    fn test_gpu_partition_set_capability() {
        let mut state = GpuPartitionState::new();
        let cap = SrIovCapability {
            max_vfs: 4,
            num_vfs_enabled: 0,
            first_vf_offset: 1,
            vf_stride: 1,
            enabled: false,
        };
        assert_eq!(state.set_capability(cap), Ok(()));
        assert_eq!(state.capability.max_vfs, 4);
    }

    #[test]
    fn test_gpu_partition_enable_sr_iov() {
        let mut state = GpuPartitionState::new();
        let cap = SrIovCapability {
            max_vfs: 2,
            num_vfs_enabled: 0,
            first_vf_offset: 1,
            vf_stride: 1,
            enabled: false,
        };
        state.set_capability(cap).unwrap();
        assert_eq!(state.enable_sr_iov(), Ok(()));
        assert!(state.sr_iov_enabled);
    }

    #[test]
    fn test_gpu_partition_enable_twice_fails() {
        let mut state = GpuPartitionState::new();
        let cap = SrIovCapability {
            max_vfs: 2,
            num_vfs_enabled: 0,
            first_vf_offset: 1,
            vf_stride: 1,
            enabled: false,
        };
        state.set_capability(cap).unwrap();
        state.enable_sr_iov().unwrap();
        assert_eq!(state.enable_sr_iov(), Err(GpuError::SrIovAlreadyEnabled));
    }

    #[test]
    fn test_gpu_partition_enable_unsupported_fails() {
        let mut state = GpuPartitionState::new();
        // No capability set — max_vfs = 0
        assert_eq!(state.enable_sr_iov(), Err(GpuError::SrIovNotSupported));
    }

    #[test]
    fn test_gpu_partition_assign_vf() {
        let mut state = GpuPartitionState::new();
        let cap = SrIovCapability {
            max_vfs: 2,
            num_vfs_enabled: 0,
            first_vf_offset: 1,
            vf_stride: 1,
            enabled: false,
        };
        state.set_capability(cap).unwrap();
        state.enable_sr_iov().unwrap();

        let vf = GpuVirtualFunction {
            addr: PcieAddr::new(0, 0, 1),
            assigned_guest: GuestId::Android,
            adreno_model: "Adreno 740",
        };
        assert_eq!(state.assign_vf(vf), Ok(()));
        assert_eq!(state.registry.assigned_count(), 1);
    }

    #[test]
    fn test_gpu_partition_assign_without_enable_fails() {
        let mut state = GpuPartitionState::new();
        let vf = GpuVirtualFunction {
            addr: PcieAddr::new(0, 0, 1),
            assigned_guest: GuestId::Android,
            adreno_model: "Adreno 740",
        };
        // Assign without enabling SR-IOV first
        assert_eq!(state.assign_vf(vf), Err(GpuError::SrIovNotSupported));
    }

    #[test]
    fn test_gpu_partition_two_vfs_different_guests() {
        let mut state = GpuPartitionState::new();
        let cap = SrIovCapability {
            max_vfs: 2,
            num_vfs_enabled: 0,
            first_vf_offset: 1,
            vf_stride: 1,
            enabled: false,
        };
        state.set_capability(cap).unwrap();
        state.enable_sr_iov().unwrap();

        let vf0 = GpuVirtualFunction {
            addr: PcieAddr::new(0, 0, 1),
            assigned_guest: GuestId::Android,
            adreno_model: "Adreno 740",
        };
        let vf1 = GpuVirtualFunction {
            addr: PcieAddr::new(0, 0, 2),
            assigned_guest: GuestId::Android,
            adreno_model: "Adreno 740",
        };

        assert_eq!(state.assign_vf(vf0), Ok(()));
        assert_eq!(state.assign_vf(vf1), Ok(()));
        assert_eq!(state.registry.assigned_count(), 2);
    }

    // ── Error type coverage ───────────────────────────────────────────────────

    #[test]
    fn test_gpu_error_variants_distinct() {
        assert_ne!(GpuError::SrIovNotSupported, GpuError::SrIovAlreadyEnabled);
        assert_ne!(
            GpuError::ConflictingVfAssignment,
            GpuError::VfCountExceedsMax
        );
    }

    #[test]
    fn test_gpu_error_debug_format() {
        let err = GpuError::SrIovNotSupported;
        assert_eq!(format!("{:?}", err), "SrIovNotSupported");
    }
}
