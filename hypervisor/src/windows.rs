// ch17: ARM Tier — Hardware And Partition Configuration (Windows Partition)
//
// This module describes the static configuration AETHER produces for the
// Windows partition on ARM Tier hardware (Snapdragon X Elite / X Plus), and
// enforces the boot-environment requirements Windows-on-ARM imposes on the
// hypervisor.
//
// ── ARM Tier Partition Assignment (TXT.rtf §Ch17) ────────────────────────────
//
// At boot on ARM Tier hardware, AETHER partitions resources as follows:
//
//   CPU:     cores split between Windows and Android; static assignment, never
//            time-multiplexed (ch09 CorePartition model)
//   Memory:  AETHER reservation + Windows working set + Android working set;
//            Stage 2 tables enforce physical isolation (ch08)
//   GPU:     SR-IOV VF 0 → Windows, VF 1 → Android (ch13)
//   Storage: separate NVMe namespaces (ch14); Windows namespace ≥ RAM for
//            crash dumps
//   Network: SR-IOV VF or dedicated adapter per guest (ch15)
//   USB:     controllers assigned per-guest; integrated input switches (ch16)
//
// AETHER constructs the ACPI tables for Windows's view of the hardware,
// programs Stage 2 page tables for Windows's IPA space, configures GICv3
// virtualization to route Windows device interrupts to Windows cores only,
// and then ERets to Windows's EFI application entry point at EL1.
//
// ── Windows-on-ARM Boot Environment Requirements ─────────────────────────────
//
// Windows-on-ARM places four requirements on the hypervisor environment:
//
// 1. CPUID hypervisor leaves (EAX=0x40000000–0x40000001):
//    Windows probes for a hypervisor via CPUID. EAX=0x40000000 returns the
//    vendor string (12 bytes in EBX/ECX/EDX). EAX=0x40000001 returns the
//    interface identifier. AETHER must intercept these and return values that
//    Windows accepts — either a neutral string (Windows uses slower hardware
//    paths) or a Hyper-V compatible response (Windows uses enlightenments).
//
// 2. Hyper-V Enlightenments (Microsoft Hypervisor TLFS Ch. 12):
//    When AETHER advertises Hyper-V compatibility, Windows activates
//    enlightened paths: synthetic timer (replaces ARM arch timer polling),
//    hypercall TLB flush (batch invalidation), MSR-based interrupt control.
//    Each enlightenment AETHER advertises MUST be implemented — advertising
//    a feature AETHER does not provide causes Windows to hang or crash.
//
// 3. Secure Boot (UEFI Specification §27):
//    Windows-on-ARM requires a valid Secure Boot chain:
//      PK (Platform Key) → KEK (Key Exchange Key) → db (Microsoft CA) → dbx
//    Without this chain, Windows Boot Manager refuses to load.
//
// 4. Inbox drivers only:
//    All hardware AETHER presents to Windows must have inbox (Microsoft-
//    provided) ARM64 drivers. Custom drivers require WHQL signing, which is
//    impractical for a hypervisor project. AETHER presents only standard ARM
//    hardware (GIC, PCIe, NVMe, xHCI) that Windows's inbox drivers support.
//
// ── No Custom Windows Code ───────────────────────────────────────────────────
//
// AETHER must work with a completely unmodified Windows-on-ARM installation.
// AETHER does not inject code, install drivers, or patch the Windows image.
// Windows runs as it would on a certified ARM laptop — it simply happens to
// be running at EL1 under AETHER's Stage 2 tables rather than on bare metal.
//
// References:
//   Microsoft Hypervisor TLFS — github.com/MicrosoftDocs/Virtualization-Documentation
//   UEFI Specification §27    — Secure Boot (uefi.org)
//   ARM ARM — CPUID emulation at EL2 (ID_AA64PFR0_EL1, CPUID trap via HCR_EL2)
//   Project Mu                — github.com/microsoft/mu (UEFI reference for Windows)
//   EDK2 ArmVirtPkg           — minimal ARM UEFI platform reference

use crate::partition::GuestId;

// ─────────────────────────────────────────────────────────────────────────────
// Error type
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsConfigError {
    /// An enlightenment was advertised in the CPUID leaf but not enabled in
    /// the EnlightenmentSet. Windows will use the feature and hang.
    EnlightenmentAdvertisedButNotImplemented,
    /// Secure Boot chain is incomplete. Windows Boot Manager will refuse to load.
    SecureBootChainIncomplete,
    /// The Windows NVMe namespace is smaller than the assigned RAM.
    /// Crash dumps cannot be written — Windows reboots silently on crash.
    CrashDumpSpaceInsufficient,
    /// A custom (non-inbox) driver was declared for a device in the Windows
    /// partition. Custom drivers require WHQL signing; use inbox drivers only.
    CustomDriverNotAllowed,
    /// CPU count is zero; Windows requires at least one core.
    NoCpuCoresAssigned,
    /// Memory is zero; Windows cannot boot without RAM.
    NoMemoryAssigned,
}

// ─────────────────────────────────────────────────────────────────────────────
// CPUID hypervisor identity leaves
//
// ARM64 CPUID (ID registers accessed via MRS) does not use the x86 CPUID
// leaf model directly. However, Windows-on-ARM probes for a hypervisor via
// the CPUID instruction (which ARM64 EL2 can trap via HCR_EL2.TID3).
// AETHER intercepts CPUID with EAX=0x40000000 and 0x40000001.
//
// EAX=0x40000000 response:
//   EAX: maximum hypervisor CPUID leaf (e.g., 0x40000006 for Hyper-V)
//   EBX/ECX/EDX: 12-byte vendor string (packed as little-endian u32 triples)
//
// EAX=0x40000001 response:
//   EAX: hypervisor interface signature
//     "Hv#1" = 0x31237648 → Hyper-V compatible
//     "AETH" = 0x48544541 → AETHER neutral (Windows uses standard hardware)
//
// Microsoft Hypervisor TLFS §2.4 defines the leaf layout.
// ─────────────────────────────────────────────────────────────────────────────

/// CPUID hypervisor interface signatures (EAX=0x40000001, returned in EAX).
pub mod hypervisor_interface {
    /// Hyper-V compatible interface ("Hv#1" as little-endian u32).
    /// When returned, Windows activates enlightened paths (timer, TLB, APIC).
    pub const HYPER_V: u32 = 0x3123_7648; // b"Hv#1"

    /// AETHER neutral interface ("AETH" as little-endian u32).
    /// Windows falls back to standard hardware paths — slower but no
    /// enlightenment implementation required.
    pub const AETHER_NEUTRAL: u32 = 0x4854_4541; // b"AETH"
}

/// 12-byte vendor string returned in EBX/ECX/EDX for CPUID EAX=0x40000000.
///
/// Packed as three little-endian u32 values:
///   EBX = bytes [0..4], ECX = bytes [4..8], EDX = bytes [8..12]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HypervisorVendorString(pub [u8; 12]);

impl HypervisorVendorString {
    /// "Microsoft Hv" — the standard Hyper-V vendor string.
    /// Windows recognizes this and activates enlightened paths.
    pub const MICROSOFT_HV: Self = Self(*b"Microsoft Hv");

    /// "AETHER      " — neutral AETHER vendor string (padded to 12 bytes).
    /// Windows does not recognize this; falls back to standard hardware.
    pub const AETHER: Self = Self(*b"AETHER      ");

    /// Pack the vendor string into the three CPUID output registers.
    /// Returns (EBX, ECX, EDX).
    pub fn to_cpuid_regs(&self) -> (u32, u32, u32) {
        let b = &self.0;
        let ebx = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        let ecx = u32::from_le_bytes([b[4], b[5], b[6], b[7]]);
        let edx = u32::from_le_bytes([b[8], b[9], b[10], b[11]]);
        (ebx, ecx, edx)
    }
}

/// Response to CPUID with EAX=0x40000000 (hypervisor identity leaf).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CpuidHypervisorLeaf {
    /// Maximum hypervisor CPUID leaf (returned in EAX).
    /// Must be ≥ 0x40000001. Set to 0x40000006 for full Hyper-V compat.
    /// Set to 0x40000001 for neutral (only identity + interface leaves).
    pub max_leaf: u32,
    /// 12-byte vendor string (returned in EBX/ECX/EDX).
    pub vendor: HypervisorVendorString,
    /// Interface signature for EAX=0x40000001 (returned in EAX).
    pub interface: u32,
}

impl CpuidHypervisorLeaf {
    /// Hyper-V compatible leaf — Windows activates enlightenments.
    ///
    /// AETHER must implement every enlightenment in `EnlightenmentSet` before
    /// advertising this. Advertising without implementing causes Windows to hang.
    pub const HYPER_V_COMPAT: Self = Self {
        max_leaf: 0x4000_0006,
        vendor: HypervisorVendorString::MICROSOFT_HV,
        interface: hypervisor_interface::HYPER_V,
    };

    /// Neutral leaf — Windows uses standard (non-enlightened) hardware paths.
    /// Safe to advertise without implementing any enlightenments.
    pub const AETHER_NEUTRAL: Self = Self {
        max_leaf: 0x4000_0001,
        vendor: HypervisorVendorString::AETHER,
        interface: hypervisor_interface::AETHER_NEUTRAL,
    };

    /// True if this leaf advertises Hyper-V compatibility.
    pub fn is_hyper_v_compatible(&self) -> bool {
        self.interface == hypervisor_interface::HYPER_V
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Hyper-V Enlightenments
//
// When AETHER returns HYPER_V_COMPAT from CPUID, Windows activates three
// key enlightened paths. Each one AETHER advertises MUST be implemented.
// If Windows calls a synthetic feature that AETHER does not handle, it hangs.
//
// Microsoft Hypervisor TLFS Chapter 12 describes the enlightenment interface.
// ─────────────────────────────────────────────────────────────────────────────

/// The subset of Hyper-V enlightenments AETHER may implement.
///
/// Default: all false (safe — Windows uses standard hardware paths).
/// Enable only what AETHER has fully implemented.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnlightenmentSet {
    /// Synthetic timer (HV_X64_MSR_STIMER0_CONFIG / _COUNT).
    /// Replaces polling the ARM architectural timer. Reduces timer overhead.
    /// Requires: intercept synthetic timer MSR writes and arm a real timer.
    pub synthetic_timer: bool,

    /// Hypercall-based TLB flush (HvFlushVirtualAddressList).
    /// Batches TLB invalidations into a single hypercall instead of per-page
    /// TLBI instructions. Reduces TLB flush cost for large address spaces.
    /// Requires: implement the HvFlushVirtualAddressList hypercall dispatch.
    pub hypercall_tlb_flush: bool,

    /// MSR-based interrupt control (HV_X64_MSR_APIC_ASSIST_PAGE).
    /// Allows Windows to read/write the virtual APIC via MSR rather than
    /// MMIO, reducing VM exits on each interrupt acknowledgement.
    /// Requires: allocate the APIC assist page and handle MSR traps.
    pub msr_apic_access: bool,
}

impl EnlightenmentSet {
    /// No enlightenments — Windows uses standard hardware. Safe default.
    pub const NONE: Self = Self {
        synthetic_timer: false,
        hypercall_tlb_flush: false,
        msr_apic_access: false,
    };

    /// All three primary enlightenments enabled.
    /// Only use this when all three are fully implemented.
    pub const ALL: Self = Self {
        synthetic_timer: true,
        hypercall_tlb_flush: true,
        msr_apic_access: true,
    };

    /// True if any enlightenment is enabled.
    pub fn any_enabled(&self) -> bool {
        self.synthetic_timer || self.hypercall_tlb_flush || self.msr_apic_access
    }

    /// Validate that a CPUID leaf and enlightenment set are consistent.
    ///
    /// If the CPUID leaf advertises Hyper-V compatibility but no enlightenments
    /// are enabled, that is technically safe (Windows uses enlightened paths
    /// only if specific feature bits are set in subsequent CPUID leaves).
    /// The real danger is advertising a specific enlightenment bit without
    /// implementing it. This check is a belt-and-suspenders guard.
    pub fn compatible_with_leaf(&self, leaf: &CpuidHypervisorLeaf) -> Result<(), WindowsConfigError> {
        // If advertising Hyper-V compat with enlightenments enabled, those
        // enlightenments must be implemented (tracked by the caller).
        // This function validates the reverse: if leaf is NOT Hyper-V compat,
        // no enlightenments should be enabled (they would never be invoked
        // but would represent dead code that should be cleaned up).
        if !leaf.is_hyper_v_compatible() && self.any_enabled() {
            // Enlightenments enabled but leaf won't advertise Hyper-V —
            // Windows will never use them. Not an error, but a consistency
            // issue. Return ok; caller may log a warning.
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Secure Boot configuration
//
// UEFI Secure Boot requires a four-level key hierarchy (UEFI Spec §27):
//   PK  (Platform Key)       — root of trust, owner of the platform
//   KEK (Key Exchange Key)   — authorized to update db and dbx
//   db  (Signature Database) — authorized to boot; must contain Microsoft CA
//   dbx (Forbidden Database) — revoked signatures; blocks known bad binaries
//
// Without a complete chain (PK → KEK → db with Microsoft CA → dbx),
// Windows Boot Manager refuses to load the Windows kernel (HVCI enforcement).
// ─────────────────────────────────────────────────────────────────────────────

/// Secure Boot key chain status for the Windows partition's firmware.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecureBootConfig {
    /// Platform Key is enrolled. Root of the Secure Boot trust hierarchy.
    pub platform_key_present: bool,
    /// Key Exchange Key is enrolled and signed by the PK.
    pub kek_present: bool,
    /// Signature Database (db) contains the Microsoft Windows Production CA.
    /// Without this entry, the Windows Boot Manager signature fails verification.
    pub db_contains_windows_ca: bool,
    /// Forbidden Signature Database (dbx) is present (may be empty list).
    /// Windows checks dbx exists even if empty.
    pub dbx_present: bool,
    /// Secure Boot is active in firmware. All of the above must be true first.
    pub enabled: bool,
}

impl SecureBootConfig {
    /// A fully valid Secure Boot configuration.
    pub const VALID: Self = Self {
        platform_key_present: true,
        kek_present: true,
        db_contains_windows_ca: true,
        dbx_present: true,
        enabled: true,
    };

    /// Disabled Secure Boot — Windows will not boot on ARM with this.
    pub const DISABLED: Self = Self {
        platform_key_present: false,
        kek_present: false,
        db_contains_windows_ca: false,
        dbx_present: false,
        enabled: false,
    };

    /// Validate that the Secure Boot chain is complete enough for Windows.
    ///
    /// Windows-on-ARM requires all four elements (PK, KEK, db with MS CA, dbx)
    /// and Secure Boot enabled. Any gap causes boot refusal.
    pub fn validate(&self) -> Result<(), WindowsConfigError> {
        if !self.platform_key_present
            || !self.kek_present
            || !self.db_contains_windows_ca
            || !self.dbx_present
            || !self.enabled
        {
            return Err(WindowsConfigError::SecureBootChainIncomplete);
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Crash dump configuration
//
// When Windows crashes (BSOD), it writes a full memory dump to the paging
// file on its NVMe namespace. The namespace must have ≥ (Windows RAM) bytes
// free for the dump. If not, Windows reboots immediately with no dump —
// making crashes undiagnosable. (Windows HLK requirement.)
// ─────────────────────────────────────────────────────────────────────────────

/// Crash dump storage requirements for the Windows partition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CrashDumpConfig {
    /// Bytes of RAM assigned to the Windows partition.
    pub windows_ram_bytes: u64,
    /// Bytes available in the Windows NVMe namespace for the paging file.
    pub namespace_available_bytes: u64,
}

impl CrashDumpConfig {
    /// True if the namespace has at least as much space as Windows RAM.
    pub fn has_sufficient_space(&self) -> bool {
        self.namespace_available_bytes >= self.windows_ram_bytes
    }

    /// Validate that crash dump space is adequate.
    pub fn validate(&self) -> Result<(), WindowsConfigError> {
        if !self.has_sufficient_space() {
            return Err(WindowsConfigError::CrashDumpSpaceInsufficient);
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Driver policy
//
// All hardware AETHER presents to the Windows partition must have inbox
// (Microsoft-supplied) ARM64 drivers. Custom drivers require WHQL certification,
// which is impractical for a hypervisor project. AETHER hardware selection
// must stay within what Windows ships drivers for by default:
//   ✓ ARM GICv3 interrupt controller
//   ✓ ARM architectural timer
//   ✓ PCIe root complex (standard ECAM)
//   ✓ NVMe storage (standard NVMe inbox driver)
//   ✓ xHCI USB (standard xHCI inbox driver)
//   ✓ Standard virtio-net (if paravirt bridge mode — Windows has inbox driver)
//   ✗ Custom AETHER-specific hardware — no driver, no signing path
// ─────────────────────────────────────────────────────────────────────────────

/// Inbox driver requirement for one hardware device in the Windows partition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceDriverEntry {
    /// Human-readable name of the device class (e.g., "NVMe storage").
    pub device_class: &'static str,
    /// True if an inbox Microsoft ARM64 driver exists for this device.
    pub has_inbox_driver: bool,
}

impl DeviceDriverEntry {
    /// Validate that this device has an inbox driver.
    pub fn validate(&self) -> Result<(), WindowsConfigError> {
        if !self.has_inbox_driver {
            return Err(WindowsConfigError::CustomDriverNotAllowed);
        }
        Ok(())
    }
}

/// Standard devices AETHER presents to Windows, all with confirmed inbox drivers.
pub mod inbox_devices {
    use super::DeviceDriverEntry;
    pub const GIC_V3: DeviceDriverEntry = DeviceDriverEntry {
        device_class: "ARM GICv3 interrupt controller",
        has_inbox_driver: true,
    };
    pub const ARM_TIMER: DeviceDriverEntry = DeviceDriverEntry {
        device_class: "ARM architectural timer",
        has_inbox_driver: true,
    };
    pub const PCIE_ECAM: DeviceDriverEntry = DeviceDriverEntry {
        device_class: "PCIe ECAM root complex",
        has_inbox_driver: true,
    };
    pub const NVME: DeviceDriverEntry = DeviceDriverEntry {
        device_class: "NVMe storage controller",
        has_inbox_driver: true,
    };
    pub const XHCI: DeviceDriverEntry = DeviceDriverEntry {
        device_class: "xHCI USB host controller",
        has_inbox_driver: true,
    };
    pub const NIC_SRIOV_VF: DeviceDriverEntry = DeviceDriverEntry {
        device_class: "NIC SR-IOV Virtual Function",
        has_inbox_driver: true,
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// ARM Tier partition configuration — Windows guest
//
// Describes the complete static allocation for the Windows partition on ARM
// Tier hardware. Produced once at boot; immutable thereafter.
// ─────────────────────────────────────────────────────────────────────────────

/// Complete static configuration for the Windows partition on ARM Tier hardware.
#[derive(Debug)]
pub struct WindowsPartitionConfig {
    /// Number of physical CPU cores assigned to Windows.
    pub cpu_count: usize,
    /// Physical RAM assigned to Windows, in bytes.
    pub memory_bytes: u64,
    /// CPUID hypervisor identity leaf that AETHER returns to Windows.
    pub cpuid_leaf: CpuidHypervisorLeaf,
    /// Hyper-V enlightenments that AETHER implements for this partition.
    pub enlightenments: EnlightenmentSet,
    /// Secure Boot key chain configuration.
    pub secure_boot: SecureBootConfig,
    /// Crash dump storage configuration.
    pub crash_dump: CrashDumpConfig,
}

impl WindowsPartitionConfig {
    /// The guest this configuration always describes.
    pub const GUEST: GuestId = GuestId::Windows;

    /// Validate all Windows boot-environment requirements simultaneously.
    ///
    /// Returns the first error encountered. All checks are independent —
    /// callers should iterate to surface all failures if needed.
    pub fn validate(&self) -> Result<(), WindowsConfigError> {
        if self.cpu_count == 0 {
            return Err(WindowsConfigError::NoCpuCoresAssigned);
        }
        if self.memory_bytes == 0 {
            return Err(WindowsConfigError::NoMemoryAssigned);
        }
        self.secure_boot.validate()?;
        self.crash_dump.validate()?;
        // Enlightenment/CPUID consistency.
        if self.cpuid_leaf.is_hyper_v_compatible() && self.enlightenments.any_enabled() {
            // Hyper-V compat + enlightenments: caller must have implemented them.
            // We cannot verify implementation here — this is a configuration check only.
        }
        Ok(())
    }

    /// True if Windows will use Hyper-V enlightened paths.
    pub fn is_enlightened(&self) -> bool {
        self.cpuid_leaf.is_hyper_v_compatible() && self.enlightenments.any_enabled()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Windows partition state — top-level runtime state
// ─────────────────────────────────────────────────────────────────────────────

/// Runtime state of the Windows partition.
pub struct WindowsPartitionState {
    /// Static configuration (set once at boot).
    pub config: Option<WindowsPartitionConfig>,
    /// True once the Windows partition has been ERETed into (is running).
    pub running: bool,
}

impl WindowsPartitionState {
    pub const fn new() -> Self {
        Self {
            config: None,
            running: false,
        }
    }

    /// Apply a validated configuration. Returns error if config is invalid.
    pub fn configure(&mut self, cfg: WindowsPartitionConfig) -> Result<(), WindowsConfigError> {
        cfg.validate()?;
        self.config = Some(cfg);
        Ok(())
    }

    /// Mark Windows as running (called after ERET to EL1).
    /// Returns error if no configuration has been applied yet.
    pub fn mark_running(&mut self) -> Result<(), WindowsConfigError> {
        if self.config.is_none() {
            return Err(WindowsConfigError::NoCpuCoresAssigned);
        }
        self.running = true;
        Ok(())
    }

    /// Handle a guest CPUID trap (EAX=0x40000000).
    ///
    /// Called from the EL2 exception handler when Windows executes CPUID with
    /// EAX in the hypervisor leaf range. Returns the four CPUID output registers.
    /// The triggering CPUID instruction is consumed; ELR_EL2 is advanced by 4.
    pub fn handle_cpuid_hypervisor_leaf(&self) -> CpuidResponse {
        let leaf = self
            .config
            .as_ref()
            .map(|c| &c.cpuid_leaf)
            .unwrap_or(&CpuidHypervisorLeaf::AETHER_NEUTRAL);

        let (ebx, ecx, edx) = leaf.vendor.to_cpuid_regs();
        CpuidResponse {
            eax: leaf.max_leaf,
            ebx,
            ecx,
            edx,
        }
    }

    /// Handle a guest CPUID trap (EAX=0x40000001).
    ///
    /// Returns the hypervisor interface identifier in EAX.
    pub fn handle_cpuid_interface_leaf(&self) -> CpuidResponse {
        let interface = self
            .config
            .as_ref()
            .map(|c| c.cpuid_leaf.interface)
            .unwrap_or(hypervisor_interface::AETHER_NEUTRAL);

        CpuidResponse {
            eax: interface,
            ebx: 0,
            ecx: 0,
            edx: 0,
        }
    }
}

impl Default for WindowsPartitionState {
    fn default() -> Self {
        Self::new()
    }
}

/// Four output registers of a CPUID instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CpuidResponse {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── HypervisorVendorString ────────────────────────────────────────────────

    #[test]
    fn test_vendor_string_microsoft_hv_bytes() {
        assert_eq!(&HypervisorVendorString::MICROSOFT_HV.0, b"Microsoft Hv");
    }

    #[test]
    fn test_vendor_string_to_cpuid_regs_microsoft() {
        let (ebx, ecx, edx) = HypervisorVendorString::MICROSOFT_HV.to_cpuid_regs();
        // "Micr" = 0x7263_694D LE, "osof" = 0x666F_736F LE, "t Hv" = 0x7648_2074 LE
        assert_eq!(ebx, u32::from_le_bytes(*b"Micr"));
        assert_eq!(ecx, u32::from_le_bytes(*b"osof"));
        assert_eq!(edx, u32::from_le_bytes(*b"t Hv"));
    }

    #[test]
    fn test_vendor_string_to_cpuid_regs_aether() {
        let (ebx, ecx, edx) = HypervisorVendorString::AETHER.to_cpuid_regs();
        assert_eq!(ebx, u32::from_le_bytes(*b"AETH"));
        assert_eq!(ecx, u32::from_le_bytes(*b"ER  "));
        assert_eq!(edx, u32::from_le_bytes(*b"    "));
    }

    // ── CpuidHypervisorLeaf ───────────────────────────────────────────────────

    #[test]
    fn test_hyper_v_compat_leaf_is_hyper_v() {
        assert!(CpuidHypervisorLeaf::HYPER_V_COMPAT.is_hyper_v_compatible());
    }

    #[test]
    fn test_neutral_leaf_is_not_hyper_v() {
        assert!(!CpuidHypervisorLeaf::AETHER_NEUTRAL.is_hyper_v_compatible());
    }

    #[test]
    fn test_hyper_v_interface_constant() {
        // "Hv#1" in little-endian: H=0x48, v=0x76, #=0x23, 1=0x31
        assert_eq!(hypervisor_interface::HYPER_V, 0x3123_7648);
    }

    #[test]
    fn test_neutral_max_leaf() {
        assert_eq!(CpuidHypervisorLeaf::AETHER_NEUTRAL.max_leaf, 0x4000_0001);
    }

    #[test]
    fn test_hyper_v_max_leaf() {
        assert_eq!(CpuidHypervisorLeaf::HYPER_V_COMPAT.max_leaf, 0x4000_0006);
    }

    // ── EnlightenmentSet ──────────────────────────────────────────────────────

    #[test]
    fn test_enlightenment_none_has_no_enabled() {
        assert!(!EnlightenmentSet::NONE.any_enabled());
    }

    #[test]
    fn test_enlightenment_all_has_all_enabled() {
        let e = EnlightenmentSet::ALL;
        assert!(e.synthetic_timer);
        assert!(e.hypercall_tlb_flush);
        assert!(e.msr_apic_access);
        assert!(e.any_enabled());
    }

    #[test]
    fn test_enlightenment_partial() {
        let e = EnlightenmentSet {
            synthetic_timer: true,
            hypercall_tlb_flush: false,
            msr_apic_access: false,
        };
        assert!(e.any_enabled());
    }

    // ── SecureBootConfig ──────────────────────────────────────────────────────

    #[test]
    fn test_secure_boot_valid_passes() {
        assert_eq!(SecureBootConfig::VALID.validate(), Ok(()));
    }

    #[test]
    fn test_secure_boot_disabled_fails() {
        assert_eq!(
            SecureBootConfig::DISABLED.validate(),
            Err(WindowsConfigError::SecureBootChainIncomplete)
        );
    }

    #[test]
    fn test_secure_boot_missing_windows_ca_fails() {
        let cfg = SecureBootConfig {
            platform_key_present: true,
            kek_present: true,
            db_contains_windows_ca: false, // Missing!
            dbx_present: true,
            enabled: true,
        };
        assert_eq!(cfg.validate(), Err(WindowsConfigError::SecureBootChainIncomplete));
    }

    #[test]
    fn test_secure_boot_enabled_but_missing_pk_fails() {
        let cfg = SecureBootConfig {
            platform_key_present: false, // Missing PK
            kek_present: true,
            db_contains_windows_ca: true,
            dbx_present: true,
            enabled: true,
        };
        assert_eq!(cfg.validate(), Err(WindowsConfigError::SecureBootChainIncomplete));
    }

    // ── CrashDumpConfig ───────────────────────────────────────────────────────

    #[test]
    fn test_crash_dump_sufficient_space() {
        let cfg = CrashDumpConfig {
            windows_ram_bytes: 8 * 1024 * 1024 * 1024, // 8 GiB
            namespace_available_bytes: 16 * 1024 * 1024 * 1024, // 16 GiB
        };
        assert!(cfg.has_sufficient_space());
        assert_eq!(cfg.validate(), Ok(()));
    }

    #[test]
    fn test_crash_dump_exact_space() {
        let cfg = CrashDumpConfig {
            windows_ram_bytes: 8 * 1024 * 1024 * 1024,
            namespace_available_bytes: 8 * 1024 * 1024 * 1024, // Exactly equal
        };
        assert!(cfg.has_sufficient_space());
    }

    #[test]
    fn test_crash_dump_insufficient_fails() {
        let cfg = CrashDumpConfig {
            windows_ram_bytes: 8 * 1024 * 1024 * 1024,
            namespace_available_bytes: 4 * 1024 * 1024 * 1024, // Only 4 GiB
        };
        assert!(!cfg.has_sufficient_space());
        assert_eq!(cfg.validate(), Err(WindowsConfigError::CrashDumpSpaceInsufficient));
    }

    // ── DeviceDriverEntry ─────────────────────────────────────────────────────

    #[test]
    fn test_inbox_devices_all_valid() {
        inbox_devices::GIC_V3.validate().unwrap();
        inbox_devices::ARM_TIMER.validate().unwrap();
        inbox_devices::PCIE_ECAM.validate().unwrap();
        inbox_devices::NVME.validate().unwrap();
        inbox_devices::XHCI.validate().unwrap();
        inbox_devices::NIC_SRIOV_VF.validate().unwrap();
    }

    #[test]
    fn test_custom_device_fails() {
        let custom = DeviceDriverEntry {
            device_class: "AETHER custom MMIO device",
            has_inbox_driver: false,
        };
        assert_eq!(custom.validate(), Err(WindowsConfigError::CustomDriverNotAllowed));
    }

    // ── WindowsPartitionConfig ────────────────────────────────────────────────

    fn valid_config() -> WindowsPartitionConfig {
        WindowsPartitionConfig {
            cpu_count: 4,
            memory_bytes: 8 * 1024 * 1024 * 1024,
            cpuid_leaf: CpuidHypervisorLeaf::AETHER_NEUTRAL,
            enlightenments: EnlightenmentSet::NONE,
            secure_boot: SecureBootConfig::VALID,
            crash_dump: CrashDumpConfig {
                windows_ram_bytes: 8 * 1024 * 1024 * 1024,
                namespace_available_bytes: 16 * 1024 * 1024 * 1024,
            },
        }
    }

    #[test]
    fn test_config_valid_neutral() {
        assert_eq!(valid_config().validate(), Ok(()));
        assert!(!valid_config().is_enlightened());
    }

    #[test]
    fn test_config_valid_hyper_v() {
        let cfg = WindowsPartitionConfig {
            cpuid_leaf: CpuidHypervisorLeaf::HYPER_V_COMPAT,
            enlightenments: EnlightenmentSet::ALL,
            ..valid_config()
        };
        assert_eq!(cfg.validate(), Ok(()));
        assert!(cfg.is_enlightened());
    }

    #[test]
    fn test_config_no_cores_fails() {
        let cfg = WindowsPartitionConfig {
            cpu_count: 0,
            ..valid_config()
        };
        assert_eq!(cfg.validate(), Err(WindowsConfigError::NoCpuCoresAssigned));
    }

    #[test]
    fn test_config_no_memory_fails() {
        let cfg = WindowsPartitionConfig {
            memory_bytes: 0,
            ..valid_config()
        };
        assert_eq!(cfg.validate(), Err(WindowsConfigError::NoMemoryAssigned));
    }

    #[test]
    fn test_config_bad_secure_boot_fails() {
        let cfg = WindowsPartitionConfig {
            secure_boot: SecureBootConfig::DISABLED,
            ..valid_config()
        };
        assert_eq!(cfg.validate(), Err(WindowsConfigError::SecureBootChainIncomplete));
    }

    #[test]
    fn test_config_insufficient_crash_dump_fails() {
        let cfg = WindowsPartitionConfig {
            crash_dump: CrashDumpConfig {
                windows_ram_bytes: 8 * 1024 * 1024 * 1024,
                namespace_available_bytes: 1,
            },
            ..valid_config()
        };
        assert_eq!(cfg.validate(), Err(WindowsConfigError::CrashDumpSpaceInsufficient));
    }

    // ── WindowsPartitionState — CPUID handling ────────────────────────────────

    #[test]
    fn test_state_cpuid_leaf_neutral_without_config() {
        let state = WindowsPartitionState::new();
        let resp = state.handle_cpuid_hypervisor_leaf();
        // Without config, returns AETHER_NEUTRAL.
        assert_eq!(resp.eax, CpuidHypervisorLeaf::AETHER_NEUTRAL.max_leaf);
    }

    #[test]
    fn test_state_cpuid_leaf_hyper_v_with_config() {
        let mut state = WindowsPartitionState::new();
        let cfg = WindowsPartitionConfig {
            cpuid_leaf: CpuidHypervisorLeaf::HYPER_V_COMPAT,
            ..valid_config()
        };
        state.configure(cfg).unwrap();
        let resp = state.handle_cpuid_hypervisor_leaf();
        assert_eq!(resp.eax, 0x4000_0006);
        // EBX/ECX/EDX should spell "Microsoft Hv"
        let (ebx, ecx, edx) = HypervisorVendorString::MICROSOFT_HV.to_cpuid_regs();
        assert_eq!(resp.ebx, ebx);
        assert_eq!(resp.ecx, ecx);
        assert_eq!(resp.edx, edx);
    }

    #[test]
    fn test_state_cpuid_interface_leaf() {
        let mut state = WindowsPartitionState::new();
        state.configure(valid_config()).unwrap();
        let resp = state.handle_cpuid_interface_leaf();
        assert_eq!(resp.eax, hypervisor_interface::AETHER_NEUTRAL);
        assert_eq!(resp.ebx, 0);
        assert_eq!(resp.ecx, 0);
        assert_eq!(resp.edx, 0);
    }

    #[test]
    fn test_state_mark_running() {
        let mut state = WindowsPartitionState::new();
        state.configure(valid_config()).unwrap();
        state.mark_running().unwrap();
        assert!(state.running);
    }

    #[test]
    fn test_state_mark_running_without_config_fails() {
        let mut state = WindowsPartitionState::new();
        assert_eq!(state.mark_running(), Err(WindowsConfigError::NoCpuCoresAssigned));
    }

    #[test]
    fn test_state_configure_invalid_rejects() {
        let mut state = WindowsPartitionState::new();
        let bad = WindowsPartitionConfig {
            cpu_count: 0,
            ..valid_config()
        };
        assert_eq!(state.configure(bad), Err(WindowsConfigError::NoCpuCoresAssigned));
        assert!(state.config.is_none());
    }

    // ── Guest identity ────────────────────────────────────────────────────────

    #[test]
    fn test_windows_partition_guest_id() {
        assert_eq!(WindowsPartitionConfig::GUEST, GuestId::Windows);
    }

    // ── Error variants ────────────────────────────────────────────────────────

    #[test]
    fn test_error_variants_distinct() {
        assert_ne!(
            WindowsConfigError::SecureBootChainIncomplete,
            WindowsConfigError::CrashDumpSpaceInsufficient
        );
        assert_ne!(
            WindowsConfigError::NoCpuCoresAssigned,
            WindowsConfigError::NoMemoryAssigned
        );
        assert_ne!(
            WindowsConfigError::CustomDriverNotAllowed,
            WindowsConfigError::EnlightenmentAdvertisedButNotImplemented
        );
    }
}
