// ch14: Storage Partitioning
//
// Storage isolation is achieved at the NVMe namespace level. An NVMe SSD can
// present multiple namespaces — each appears as a separate block device with
// its own size, LBA format, and access control. AETHER assigns one namespace
// exclusively to each guest and, where the controller supports SR-IOV, assigns
// a Virtual Function to each guest so the guest's NVMe driver talks to a
// dedicated controller with only its namespace attached.
//
// Boot-time sequence:
//   1. Identify Controller — verify the NVMe PF supports namespace management
//      and (optionally) SR-IOV
//   2. Create Namespace — issue Namespace Management (opcode 0x0D, sel=0) for
//      each guest partition; record the returned NSID
//   3. Enable SR-IOV (if supported) — enumerate VFs as in ch13 GPU model
//   4. Attach Namespace — issue Namespace Attachment (opcode 0x15, sel=0) to
//      bind each NSID exclusively to its guest's controller/VF
//   5. Registry update — record ownership; prevent cross-partition access
//
// After setup, guest NVMe drivers issue reads and writes directly to the
// controller. The hypervisor is not in the data path. A read from Android
// cannot reach the Windows namespace because the NVMe controller enforces
// namespace attachment isolation in hardware.
//
// NVMe command formats follow the NVM Express Base Specification r2.1:
//   §5.15  Namespace Management (opcode 0x0D)
//   §5.16  Namespace Attachment (opcode 0x15)
//   §5.6   Identify (opcode 0x06), CNS = 0x01 (controller) / 0x02 (active ns)
//
// LBA format: Android uses 4096-byte logical blocks (LBADS = 12, i.e., 2^12).
// This matches Android's block layer assumption and avoids the read-modify-write
// overhead of 512-byte sectors with 4K filesystem blocks.
//
// SR-IOV on NVMe: the Virtual Function model mirrors ch13 (GPU SR-IOV). Each
// VF appears as a separate NVMe controller. The PF's namespace management
// commands create and attach namespaces; VF controllers only see the namespaces
// explicitly attached to them.
//
// References:
//   NVM Express Base Specification r2.1 — nvmexpress.org (free download)
//   linux-ref/drivers/nvme/host/core.c — Linux NVMe host driver
//   linux-ref/drivers/nvme/host/pci.c  — PCIe-specific NVMe init
//   linux-ref/drivers/nvme/target/     — NVMe target (namespace isolation ref)

use crate::partition::GuestId;
use crate::passthrough::PcieAddr;

// ─────────────────────────────────────────────────────────────────────────────
// Error type
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageError {
    /// NVMe controller does not support Namespace Management (OAES bit 3 clear).
    NamespaceManagementUnsupported,
    /// NSID 0 is reserved; valid NSIDs start at 1.
    InvalidNsid,
    /// Namespace is already attached to another guest's controller.
    /// Attaching again would break storage isolation.
    NamespaceAlreadyAttached,
    /// Namespace has not been created yet; cannot attach.
    NamespaceNotFound,
    /// SR-IOV not supported by this NVMe controller.
    SrIovNotSupported,
    /// SR-IOV is already enabled; cannot reconfigure.
    SrIovAlreadyEnabled,
    /// Requested VF count exceeds the controller's MaxVFs.
    VfCountExceedsMax,
    /// Registry is at capacity (MAX_NS_COUNT namespaces already created).
    RegistryFull,
    /// LBA Data Size shift is not a supported value (must be 9 or 12).
    UnsupportedLbaShift,
}

// ─────────────────────────────────────────────────────────────────────────────
// Namespace identifier
//
// NSIDs are 1-based. NSID 0 is reserved (NVMe Base Spec §5.15.2.1).
// NSID 0xFFFF_FFFF is the broadcast NSID (applies to all namespaces).
// AETHER never uses the broadcast NSID in assignment operations.
// ─────────────────────────────────────────────────────────────────────────────

/// Namespace identifier (1-based; 0 is invalid per NVMe spec §6.1.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct NsId(pub u32);

impl NsId {
    /// NSID reserved as "not assigned" / invalid.
    pub const INVALID: NsId = NsId(0);

    /// Validate that this NSID is usable (non-zero, non-broadcast).
    pub fn is_valid(self) -> bool {
        self.0 != 0 && self.0 != 0xFFFF_FFFF
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LBA format
//
// The LBAF (LBA Format) describes the logical block size as a power-of-two
// shift (LBADS field in NVMe Identify Namespace data structure, §5.6.1 table).
// AETHER supports only two values:
//   9  → 512-byte blocks (legacy; not recommended for Android)
//   12 → 4096-byte blocks (Android-standard; matches ext4/f2fs default)
// ─────────────────────────────────────────────────────────────────────────────

/// Log2 of the LBA size in bytes (LBADS field, NVMe spec §5.6.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum LbaShift {
    /// 512-byte logical blocks (LBADS = 9).
    Lba512 = 9,
    /// 4096-byte logical blocks (LBADS = 12). Android-standard.
    Lba4096 = 12,
}

impl LbaShift {
    /// Block size in bytes.
    pub fn block_size(self) -> u64 {
        1u64 << (self as u8)
    }

    /// Construct from a raw LBADS value. Returns error if unsupported.
    pub fn from_raw(lbads: u8) -> Result<Self, StorageError> {
        match lbads {
            9 => Ok(LbaShift::Lba512),
            12 => Ok(LbaShift::Lba4096),
            _ => Err(StorageError::UnsupportedLbaShift),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NVMe admin command encoding
//
// NVMe Submission Queue Entry (SQE) layout (NVMe Base Spec §4.6.1):
//
//   CDW0  [7:0]  = Opcode
//   CDW0  [9:8]  = Fuse (00 = standalone command)
//   CDW0  [15:14]= PSDT (PRP = 00, SGL = 01/10)
//   CDW0  [31:16]= Command Identifier (CID)
//   CDW1         = NSID
//   CDW2..3      = Reserved
//   CDW4..5      = MPTR (metadata pointer)
//   CDW6..7      = DPTR (PRP1 / SGL descriptor)
//   CDW8..9      = DPTR (PRP2 / SGL segment)
//   CDW10..15    = Command-specific DWORDs
//
// This structure is used to verify the opcode constants and command selector
// fields encoded in AETHER's storage init path. In production, the admin SQE
// is written directly into the controller's Admin Submission Queue MMIO ring.
// ─────────────────────────────────────────────────────────────────────────────

/// NVMe admin command opcodes (NVMe Base Spec §5, Table 5).
pub mod opcode {
    /// Identify — query controller or namespace capabilities (§5.6).
    pub const IDENTIFY: u8 = 0x06;
    /// Namespace Management — create or delete namespaces (§5.15).
    pub const NS_MANAGEMENT: u8 = 0x0D;
    /// Namespace Attachment — attach/detach namespaces to controllers (§5.16).
    pub const NS_ATTACHMENT: u8 = 0x15;
}

/// Selector field (CDW10[3:0]) for Namespace Management (§5.15.1).
pub mod ns_mgmt_sel {
    /// Create namespace.
    pub const CREATE: u8 = 0x00;
    /// Delete namespace.
    pub const DELETE: u8 = 0x01;
}

/// Selector field (CDW10[3:0]) for Namespace Attachment (§5.16.1).
pub mod ns_attach_sel {
    /// Attach controllers to namespace.
    pub const ATTACH: u8 = 0x00;
    /// Detach controllers from namespace.
    pub const DETACH: u8 = 0x01;
}

/// Namespace Management Create Data Structure (NVMe Base Spec §5.15.2.1).
///
/// Written into the data buffer pointed to by PRP1 when issuing
/// Namespace Management with sel=CREATE. Fields that AETHER always
/// sets to zero are omitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NsCreateParams {
    /// Namespace Size in logical blocks (NSZE). Total raw capacity.
    pub nsze: u64,
    /// Namespace Capacity in logical blocks (NCAP). Available capacity.
    /// AETHER sets NCAP = NSZE (no thin provisioning).
    pub ncap: u64,
    /// LBA Format index (FLBAS[3:0]). Selects from the controller's
    /// supported LBAF table; AETHER looks up the 4096-byte format index.
    pub flbas_index: u8,
    /// LBA Data Size shift (from the selected LBAF).
    pub lba_shift: LbaShift,
}

impl NsCreateParams {
    /// Build parameters for an Android namespace.
    ///
    /// `size_bytes` is the desired namespace size. It is rounded down to
    /// a whole number of 4096-byte LBAs.
    pub fn android(size_bytes: u64) -> Self {
        let lba_shift = LbaShift::Lba4096;
        let block_size = lba_shift.block_size();
        let nsze = size_bytes / block_size;
        Self {
            nsze,
            ncap: nsze,
            flbas_index: 0, // index resolved at runtime from Identify Namespace
            lba_shift,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NVMe controller capabilities (from Identify Controller response)
//
// In production, AETHER reads the Identify Controller Data Structure
// (CNS = 0x01) from the controller's Admin Completion Queue. The fields
// below are the subset AETHER needs to gate namespace management operations.
// ─────────────────────────────────────────────────────────────────────────────

/// Subset of NVMe Identify Controller data (NVMe Base Spec §5.6.1, Table 97).
#[derive(Clone, Copy, Debug)]
pub struct NvmeControllerCaps {
    /// Controller supports Namespace Management and Attachment commands.
    /// Derived from OACS[3] (Optional Admin Command Support, bit 3).
    pub namespace_management: bool,
    /// Maximum number of namespaces this controller can manage.
    /// Derived from NN field. Typically 1024 on enterprise, 1–8 on consumer.
    pub max_namespaces: u32,
    /// Controller supports SR-IOV (derived from PCIe SR-IOV Extended Cap presence).
    pub sr_iov_supported: bool,
    /// Maximum VFs supported (from SR-IOV Extended Capability MaxVFs field).
    pub max_vfs: u16,
}

impl NvmeControllerCaps {
    /// Minimal caps for a controller that supports namespace management but not SR-IOV.
    pub const fn management_only(max_namespaces: u32) -> Self {
        Self {
            namespace_management: true,
            max_namespaces,
            sr_iov_supported: false,
            max_vfs: 0,
        }
    }

    /// Caps for a controller supporting both namespace management and SR-IOV.
    pub const fn with_sr_iov(max_namespaces: u32, max_vfs: u16) -> Self {
        Self {
            namespace_management: true,
            max_namespaces,
            sr_iov_supported: true,
            max_vfs,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NVMe Virtual Function (SR-IOV path)
//
// When the NVMe controller supports SR-IOV, each guest gets a dedicated VF.
// The guest's NVMe driver sees only the namespaces attached to its VF's
// controller ID. Namespace attachment is done against the VF's Controller ID
// (CNTLID), not the PF.
// ─────────────────────────────────────────────────────────────────────────────

/// Controller ID (CNTLID) assigned by the NVMe controller (16-bit, §5.6.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControllerId(pub u16);

/// One NVMe Virtual Function assigned to a guest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NvmeVirtualFunction {
    /// PCIe BUS:DEV:FUNC address of this VF.
    pub addr: PcieAddr,
    /// NVMe Controller ID (CNTLID) for Namespace Attachment commands.
    pub controller_id: ControllerId,
    /// Guest exclusively assigned this VF.
    pub guest: GuestId,
}

// ─────────────────────────────────────────────────────────────────────────────
// Namespace descriptor
// ─────────────────────────────────────────────────────────────────────────────

/// Describes one NVMe namespace managed by AETHER.
#[derive(Clone, Copy, Debug)]
pub struct NvmeNamespace {
    /// Namespace ID (1-based).
    pub nsid: NsId,
    /// Total size in logical blocks.
    pub size_lbas: u64,
    /// LBA format in use.
    pub lba_shift: LbaShift,
    /// Guest to which this namespace is exclusively attached.
    /// `None` means the namespace exists but is not yet attached.
    pub attached_guest: Option<GuestId>,
    /// Controller ID to which this namespace is attached (SR-IOV path).
    /// `None` when using single-controller (non-SR-IOV) mode.
    pub attached_controller: Option<ControllerId>,
}

impl NvmeNamespace {
    /// Total size in bytes.
    pub fn size_bytes(&self) -> u64 {
        self.size_lbas * self.lba_shift.block_size()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Namespace registry
//
// Tracks created namespaces and their exclusive assignments. Prevents:
//   • Attaching one namespace to two guests (cross-partition data access)
//   • Operating on a namespace that has not been created
//   • Creating more namespaces than MAX_NS_COUNT
// ─────────────────────────────────────────────────────────────────────────────

const MAX_NS_COUNT: usize = 16;

/// Registry of NVMe namespaces and their guest assignments.
#[derive(Debug)]
pub struct NamespaceRegistry {
    namespaces: [Option<NvmeNamespace>; MAX_NS_COUNT],
    count: usize,
}

impl NamespaceRegistry {
    pub const fn new() -> Self {
        Self {
            namespaces: [None; MAX_NS_COUNT],
            count: 0,
        }
    }

    /// Record a newly created namespace (not yet attached).
    pub fn register(&mut self, ns: NvmeNamespace) -> Result<(), StorageError> {
        if !ns.nsid.is_valid() {
            return Err(StorageError::InvalidNsid);
        }
        if self.count >= MAX_NS_COUNT {
            return Err(StorageError::RegistryFull);
        }
        self.namespaces[self.count] = Some(ns);
        self.count += 1;
        Ok(())
    }

    /// Attach a namespace to a guest (and optionally a controller in SR-IOV mode).
    ///
    /// Returns `NamespaceAlreadyAttached` if the NSID is already owned by any guest.
    pub fn attach(
        &mut self,
        nsid: NsId,
        guest: GuestId,
        controller: Option<ControllerId>,
    ) -> Result<(), StorageError> {
        let ns = self
            .namespaces
            .iter_mut()
            .flatten()
            .find(|n| n.nsid == nsid)
            .ok_or(StorageError::NamespaceNotFound)?;

        if ns.attached_guest.is_some() {
            return Err(StorageError::NamespaceAlreadyAttached);
        }

        ns.attached_guest = Some(guest);
        ns.attached_controller = controller;
        Ok(())
    }

    /// Query which guest owns a namespace.
    pub fn owner(&self, nsid: NsId) -> Option<GuestId> {
        self.namespaces
            .iter()
            .flatten()
            .find(|n| n.nsid == nsid)
            .and_then(|n| n.attached_guest)
    }

    /// Look up a namespace by NSID.
    pub fn get(&self, nsid: NsId) -> Option<&NvmeNamespace> {
        self.namespaces.iter().flatten().find(|n| n.nsid == nsid)
    }

    /// Number of namespaces registered.
    pub fn count(&self) -> usize {
        self.count
    }
}

impl Default for NamespaceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NVMe SR-IOV state
// ─────────────────────────────────────────────────────────────────────────────

const MAX_NVME_VFS: usize = 8;

/// SR-IOV state for one NVMe controller.
#[derive(Debug)]
pub struct NvmeSrIovState {
    /// Whether SR-IOV is currently enabled.
    pub enabled: bool,
    /// Maximum VFs the controller supports.
    pub max_vfs: u16,
    /// BUS:DEV:FUNC increment to first VF from PF.
    pub first_vf_offset: u16,
    /// Stride between consecutive VFs.
    pub vf_stride: u16,
    vfs: [Option<NvmeVirtualFunction>; MAX_NVME_VFS],
    vf_count: usize,
}

impl NvmeSrIovState {
    pub const fn new(max_vfs: u16, first_vf_offset: u16, vf_stride: u16) -> Self {
        Self {
            enabled: false,
            max_vfs,
            first_vf_offset,
            vf_stride,
            vfs: [None; MAX_NVME_VFS],
            vf_count: 0,
        }
    }

    /// Compute the PCIe BDF of VF n given the PF's BDF.
    ///
    /// VF_BDF(n) = PF_BDF + FirstVFOffset + n × VFStride
    pub fn vf_bdf(&self, pf_bdf: u16, vf_index: u16) -> Option<u16> {
        if vf_index >= self.max_vfs {
            return None;
        }
        Some(pf_bdf.wrapping_add(self.first_vf_offset + vf_index * self.vf_stride))
    }

    /// Register an assigned VF.
    pub fn assign_vf(&mut self, vf: NvmeVirtualFunction) -> Result<(), StorageError> {
        if self.vf_count >= MAX_NVME_VFS {
            return Err(StorageError::VfCountExceedsMax);
        }
        self.vfs[self.vf_count] = Some(vf);
        self.vf_count += 1;
        Ok(())
    }

    /// Query which VF is assigned to a guest.
    pub fn vf_for_guest(&self, guest: GuestId) -> Option<&NvmeVirtualFunction> {
        self.vfs.iter().flatten().find(|v| v.guest == guest)
    }

    /// Number of VFs assigned.
    pub fn assigned_count(&self) -> usize {
        self.vf_count
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Storage partition state — top-level for one NVMe controller
//
// Manages the full lifecycle:
//   1. load_caps()    — record controller capabilities from Identify Controller
//   2. create_ns()    — record a newly created namespace (sim: caller issues SQE)
//   3. enable_sr_iov() — (optional) enable VFs if controller supports SR-IOV
//   4. assign_vf()    — register a VF→guest mapping
//   5. attach_ns()    — attach namespace to guest (enforces exclusive ownership)
// ─────────────────────────────────────────────────────────────────────────────

/// Top-level storage partitioning state for one NVMe controller.
pub struct StoragePartitionState {
    /// Controller capabilities (from Identify Controller).
    pub caps: Option<NvmeControllerCaps>,
    /// Namespace registry.
    pub registry: NamespaceRegistry,
    /// SR-IOV state (None if not supported or not enabled).
    pub sr_iov: Option<NvmeSrIovState>,
}

impl StoragePartitionState {
    pub const fn new() -> Self {
        Self {
            caps: None,
            registry: NamespaceRegistry::new(),
            sr_iov: None,
        }
    }

    /// Record capabilities discovered from Identify Controller.
    ///
    /// In production, called after reading the Identify Controller Data Structure
    /// (opcode 0x06, CNS = 0x01) from the Admin Completion Queue.
    pub fn load_caps(&mut self, caps: NvmeControllerCaps) {
        self.caps = Some(caps);
    }

    /// Record a namespace that has been created via Namespace Management (CREATE).
    ///
    /// The caller is responsible for issuing the actual NVMe admin SQE; this call
    /// records the resulting NSID into the registry for subsequent attach operations.
    pub fn create_ns(
        &mut self,
        nsid: NsId,
        params: &NsCreateParams,
    ) -> Result<(), StorageError> {
        let caps = self.caps.ok_or(StorageError::NamespaceManagementUnsupported)?;
        if !caps.namespace_management {
            return Err(StorageError::NamespaceManagementUnsupported);
        }

        let ns = NvmeNamespace {
            nsid,
            size_lbas: params.nsze,
            lba_shift: params.lba_shift,
            attached_guest: None,
            attached_controller: None,
        };
        self.registry.register(ns)
    }

    /// Enable SR-IOV on this NVMe controller.
    ///
    /// In production: writes NumVFs to the SR-IOV Control register in PCIe
    /// config space and sets the VF Enable bit, then waits for VFs to appear.
    pub fn enable_sr_iov(
        &mut self,
        first_vf_offset: u16,
        vf_stride: u16,
    ) -> Result<(), StorageError> {
        if self.sr_iov.is_some() {
            return Err(StorageError::SrIovAlreadyEnabled);
        }
        let caps = self.caps.ok_or(StorageError::SrIovNotSupported)?;
        if !caps.sr_iov_supported {
            return Err(StorageError::SrIovNotSupported);
        }

        self.sr_iov = Some(NvmeSrIovState::new(caps.max_vfs, first_vf_offset, vf_stride));
        let sr_iov = self.sr_iov.as_mut().unwrap();
        sr_iov.enabled = true;
        Ok(())
    }

    /// Register a VF→guest assignment (SR-IOV path).
    pub fn assign_vf(&mut self, vf: NvmeVirtualFunction) -> Result<(), StorageError> {
        let sr_iov = self.sr_iov.as_mut().ok_or(StorageError::SrIovNotSupported)?;
        sr_iov.assign_vf(vf)
    }

    /// Attach a namespace exclusively to a guest.
    ///
    /// In SR-IOV mode, also records the controller ID to which the Namespace
    /// Attachment command should be addressed (the VF's CNTLID).
    ///
    /// Enforces exclusive ownership: once attached, no other guest can attach
    /// the same NSID.
    pub fn attach_ns(&mut self, nsid: NsId, guest: GuestId) -> Result<(), StorageError> {
        // In SR-IOV mode, resolve the controller ID for this guest's VF.
        let controller_id = if let Some(ref sr_iov) = self.sr_iov {
            sr_iov
                .vf_for_guest(guest)
                .map(|vf| vf.controller_id)
        } else {
            None
        };

        self.registry.attach(nsid, guest, controller_id)
    }

    /// Query which guest owns a given namespace.
    pub fn ns_owner(&self, nsid: NsId) -> Option<GuestId> {
        self.registry.owner(nsid)
    }
}

impl Default for StoragePartitionState {
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

    // ── NsId ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_nsid_validity() {
        assert!(!NsId::INVALID.is_valid());
        assert!(NsId(1).is_valid());
        assert!(NsId(255).is_valid());
        // Broadcast NSID is also invalid for assignment.
        assert!(!NsId(0xFFFF_FFFF).is_valid());
    }

    // ── LbaShift ──────────────────────────────────────────────────────────────

    #[test]
    fn test_lba_shift_block_sizes() {
        assert_eq!(LbaShift::Lba512.block_size(), 512);
        assert_eq!(LbaShift::Lba4096.block_size(), 4096);
    }

    #[test]
    fn test_lba_shift_from_raw() {
        assert_eq!(LbaShift::from_raw(9), Ok(LbaShift::Lba512));
        assert_eq!(LbaShift::from_raw(12), Ok(LbaShift::Lba4096));
        assert_eq!(LbaShift::from_raw(11), Err(StorageError::UnsupportedLbaShift));
    }

    // ── NsCreateParams ────────────────────────────────────────────────────────

    #[test]
    fn test_ns_create_params_android_128gb() {
        let p = NsCreateParams::android(128 * 1024 * 1024 * 1024);
        // 128 GiB / 4096 = 33_554_432 LBAs
        assert_eq!(p.nsze, 33_554_432);
        assert_eq!(p.ncap, p.nsze);
        assert_eq!(p.lba_shift, LbaShift::Lba4096);
    }

    #[test]
    fn test_ns_create_params_rounds_down() {
        // 4097 bytes → 1 full 4096-byte LBA (1 byte truncated).
        let p = NsCreateParams::android(4097);
        assert_eq!(p.nsze, 1);
    }

    // ── NvmeNamespace ─────────────────────────────────────────────────────────

    #[test]
    fn test_namespace_size_bytes() {
        let ns = NvmeNamespace {
            nsid: NsId(1),
            size_lbas: 1024,
            lba_shift: LbaShift::Lba4096,
            attached_guest: None,
            attached_controller: None,
        };
        assert_eq!(ns.size_bytes(), 1024 * 4096);
    }

    // ── NamespaceRegistry ─────────────────────────────────────────────────────

    fn make_ns(nsid: u32) -> NvmeNamespace {
        NvmeNamespace {
            nsid: NsId(nsid),
            size_lbas: 1000,
            lba_shift: LbaShift::Lba4096,
            attached_guest: None,
            attached_controller: None,
        }
    }

    #[test]
    fn test_registry_register_and_get() {
        let mut reg = NamespaceRegistry::new();
        reg.register(make_ns(1)).unwrap();
        assert_eq!(reg.count(), 1);
        let ns = reg.get(NsId(1)).unwrap();
        assert_eq!(ns.nsid, NsId(1));
    }

    #[test]
    fn test_registry_invalid_nsid_rejected() {
        let mut reg = NamespaceRegistry::new();
        let ns = NvmeNamespace {
            nsid: NsId::INVALID,
            size_lbas: 1000,
            lba_shift: LbaShift::Lba4096,
            attached_guest: None,
            attached_controller: None,
        };
        assert_eq!(reg.register(ns), Err(StorageError::InvalidNsid));
    }

    #[test]
    fn test_registry_attach_exclusive() {
        let mut reg = NamespaceRegistry::new();
        reg.register(make_ns(1)).unwrap();
        reg.attach(NsId(1), GuestId::Android, None).unwrap();
        assert_eq!(reg.owner(NsId(1)), Some(GuestId::Android));
    }

    #[test]
    fn test_registry_double_attach_fails() {
        let mut reg = NamespaceRegistry::new();
        reg.register(make_ns(1)).unwrap();
        reg.attach(NsId(1), GuestId::Android, None).unwrap();
        // Second attach to any guest must fail.
        assert_eq!(
            reg.attach(NsId(1), GuestId::Android, None),
            Err(StorageError::NamespaceAlreadyAttached)
        );
    }

    #[test]
    fn test_registry_attach_nonexistent_fails() {
        let mut reg = NamespaceRegistry::new();
        assert_eq!(
            reg.attach(NsId(99), GuestId::Android, None),
            Err(StorageError::NamespaceNotFound)
        );
    }

    #[test]
    fn test_registry_owner_unattached_is_none() {
        let mut reg = NamespaceRegistry::new();
        reg.register(make_ns(2)).unwrap();
        assert_eq!(reg.owner(NsId(2)), None);
    }

    // ── NvmeSrIovState ────────────────────────────────────────────────────────

    #[test]
    fn test_sriov_vf_bdf_calculation() {
        // PF at BDF 0x0000, FirstVFOffset=1, VFStride=1
        let sr_iov = NvmeSrIovState::new(4, 0x0001, 0x0001);
        let pf_bdf: u16 = 0x0000;
        assert_eq!(sr_iov.vf_bdf(pf_bdf, 0), Some(0x0001));
        assert_eq!(sr_iov.vf_bdf(pf_bdf, 1), Some(0x0002));
        assert_eq!(sr_iov.vf_bdf(pf_bdf, 4), None); // out of range
    }

    #[test]
    fn test_sriov_assign_and_query() {
        let mut sr_iov = NvmeSrIovState::new(2, 1, 1);
        let vf = NvmeVirtualFunction {
            addr: PcieAddr::new(0, 0, 1),
            controller_id: ControllerId(2),
            guest: GuestId::Android,
        };
        sr_iov.assign_vf(vf).unwrap();
        assert_eq!(sr_iov.assigned_count(), 1);
        let found = sr_iov.vf_for_guest(GuestId::Android).unwrap();
        assert_eq!(found.controller_id, ControllerId(2));
    }

    // ── StoragePartitionState — full lifecycle ────────────────────────────────

    fn android_caps() -> NvmeControllerCaps {
        NvmeControllerCaps::management_only(8)
    }

    fn android_caps_sriov() -> NvmeControllerCaps {
        NvmeControllerCaps::with_sr_iov(8, 2)
    }

    #[test]
    fn test_state_no_caps_blocks_create() {
        let mut state = StoragePartitionState::new();
        let params = NsCreateParams::android(10 * 1024 * 1024 * 1024);
        assert_eq!(
            state.create_ns(NsId(1), &params),
            Err(StorageError::NamespaceManagementUnsupported)
        );
    }

    #[test]
    fn test_state_create_and_attach_android() {
        let mut state = StoragePartitionState::new();
        state.load_caps(android_caps());

        let params = NsCreateParams::android(64 * 1024 * 1024 * 1024);
        state.create_ns(NsId(1), &params).unwrap();
        state.attach_ns(NsId(1), GuestId::Android).unwrap();

        assert_eq!(state.ns_owner(NsId(1)), Some(GuestId::Android));
    }

    #[test]
    fn test_state_cross_partition_attach_fails() {
        let mut state = StoragePartitionState::new();
        state.load_caps(android_caps());

        let params = NsCreateParams::android(64 * 1024 * 1024 * 1024);
        state.create_ns(NsId(1), &params).unwrap();
        // Attach to Android first.
        state.attach_ns(NsId(1), GuestId::Android).unwrap();
        // Attempting to attach the same NSID to Windows must fail.
        assert_eq!(
            state.attach_ns(NsId(1), GuestId::Windows),
            Err(StorageError::NamespaceAlreadyAttached)
        );
    }

    #[test]
    fn test_state_sriov_full_pipeline() {
        let mut state = StoragePartitionState::new();
        state.load_caps(android_caps_sriov());

        // Enable SR-IOV.
        state.enable_sr_iov(0x0001, 0x0001).unwrap();

        // Assign Android VF.
        let vf = NvmeVirtualFunction {
            addr: PcieAddr::new(0, 0, 1),
            controller_id: ControllerId(2),
            guest: GuestId::Android,
        };
        state.assign_vf(vf).unwrap();

        // Create and attach Android namespace; controller_id resolved from VF.
        let params = NsCreateParams::android(128 * 1024 * 1024 * 1024);
        state.create_ns(NsId(1), &params).unwrap();
        state.attach_ns(NsId(1), GuestId::Android).unwrap();

        assert_eq!(state.ns_owner(NsId(1)), Some(GuestId::Android));

        // Verify controller ID was recorded.
        let ns = state.registry.get(NsId(1)).unwrap();
        assert_eq!(ns.attached_controller, Some(ControllerId(2)));
    }

    #[test]
    fn test_state_enable_sriov_twice_fails() {
        let mut state = StoragePartitionState::new();
        state.load_caps(android_caps_sriov());
        state.enable_sr_iov(1, 1).unwrap();
        assert_eq!(
            state.enable_sr_iov(1, 1),
            Err(StorageError::SrIovAlreadyEnabled)
        );
    }

    #[test]
    fn test_state_enable_sriov_without_support_fails() {
        let mut state = StoragePartitionState::new();
        state.load_caps(android_caps()); // no SR-IOV
        assert_eq!(
            state.enable_sr_iov(1, 1),
            Err(StorageError::SrIovNotSupported)
        );
    }

    #[test]
    fn test_opcode_constants() {
        assert_eq!(opcode::IDENTIFY, 0x06);
        assert_eq!(opcode::NS_MANAGEMENT, 0x0D);
        assert_eq!(opcode::NS_ATTACHMENT, 0x15);
    }

    #[test]
    fn test_ns_mgmt_sel_constants() {
        assert_eq!(ns_mgmt_sel::CREATE, 0x00);
        assert_eq!(ns_mgmt_sel::DELETE, 0x01);
    }

    #[test]
    fn test_ns_attach_sel_constants() {
        assert_eq!(ns_attach_sel::ATTACH, 0x00);
        assert_eq!(ns_attach_sel::DETACH, 0x01);
    }

    #[test]
    fn test_error_variants_distinct() {
        assert_ne!(
            StorageError::NamespaceAlreadyAttached,
            StorageError::NamespaceNotFound
        );
        assert_ne!(
            StorageError::SrIovNotSupported,
            StorageError::SrIovAlreadyEnabled
        );
    }
}
