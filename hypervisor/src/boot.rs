// ch07: Boot
//
// The boot sequence is the most critical path in the entire hypervisor.
// A single mistake here silently hangs the machine — there is no debugger,
// no network, no error message. This module implements the UEFI handoff
// phase and the final ERET transfer to EL1 that starts each guest.
//
// Sequence of operations (ARM Tier, in order):
//   1. Platform firmware loads hypervisor.efi, transfers execution to
//      efi_main() with (image_handle, system_table) per UEFI spec Section 4.1
//   2. AETHER captures ACPI RSDP from EFI Configuration Table BEFORE calling
//      ExitBootServices — firmware may unmap config table after exit
//   3. AETHER calls ExitBootServices() with mandatory retry on
//      EFI_INVALID_PARAMETER (memory map key may stale between calls)
//   4. After exit: firmware boot services are gone. AETHER parses the
//      returned memory map to categorise every physical memory region
//   5. Stage 2 page tables are constructed (Chapter 8, not this module)
//   6. For each guest: write ELR_EL2 (entry point) + SPSR_EL2 (EL1h state)
//      + x0 (DTB address), then execute ERET → guest runs at EL1
//
// Design invariants enforced here:
//   - ExitBootServices MUST be called exactly once (static flag)
//   - Memory map parsing MUST use descriptor_size as stride (not sizeof)
//   - ERET to EL1 uses SPSR_EL2 = GUEST_ENTRY_EL1H (all interrupts masked)
//     so the guest kernel initialises before any interrupt can fire
//
// Skill guide warnings (ch07-boot.md):
//   - ExitBootServices must retry on EFI_INVALID_PARAMETER — this file does
//   - Do NOT call any EFI boot services after ExitBootServices returns
//   - ACPI tables are NOT contiguous — each has its own physical address
//   - "Physical addresses" in pre-MMU boot code are truly physical
//
// Primary references:
//   - UEFI Specification 2.10, Chapters 4, 7, 8 (uefi.org)
//   - ACPI Specification 6.5, Chapters 5–6 (uefi.org)
//   - ARM SBBR DEN0044 — ARM-compliant firmware requirements
//   - linux-ref/arch/arm64/include/asm/efi.h
//   - linux-ref/drivers/firmware/efi/libstub/arm64-stub.c

#[cfg(target_arch = "aarch64")]
use core::arch::asm;
use core::ffi::c_void;

#[cfg(target_arch = "aarch64")]
use crate::arm64::regs::{spsr_el2, write_elr_el2, write_spsr_el2};

// ─────────────────────────────────────────────────────────────────────────────
// EFI primitive types
//
// All types match the UEFI Specification definitions. On ARM64/x86-64,
// UINTN = usize = 8 bytes.
//
// Source: UEFI Specification 2.10 Section 2.3.1 (Data Types)
// ─────────────────────────────────────────────────────────────────────────────

/// EFI status code. 0 = success. High bit set = error.
/// Source: UEFI Spec Section 2.3.1, Appendix D.
pub type EfiStatus = usize;

/// Opaque handle to an EFI object (image, protocol, device path).
/// On ARM64 this is a 64-bit pointer.
pub type EfiHandle = *mut c_void;

/// EFI physical address — 64-bit on ARM64.
pub type EfiPhysicalAddress = u64;

// ── Status codes used by the boot sequence ─────────────────────────────────

/// Successful completion.
/// Source: UEFI Spec Appendix D.
pub const EFI_SUCCESS: EfiStatus = 0;

/// The buffer was not large enough (GetMemoryMap returns this with the
/// required size written back through `map_size`).
/// Source: UEFI Spec Appendix D, error code 5.
pub const EFI_BUFFER_TOO_SMALL: EfiStatus = 0x8000_0000_0000_0005;

/// Stale memory map key — the map changed between GetMemoryMap and
/// ExitBootServices. The *only* correct response is to retry both calls.
/// Source: UEFI Spec Section 7.4.6 (ExitBootServices).
pub const EFI_INVALID_PARAMETER: EfiStatus = 0x8000_0000_0000_0002;

// ─────────────────────────────────────────────────────────────────────────────
// EFI Table Header
//
// Common 24-byte prefix for every EFI table (SystemTable, BootServices, etc.)
//
// Source: UEFI Spec 2.10 Section 4.2 (EFI_TABLE_HEADER)
// ─────────────────────────────────────────────────────────────────────────────

#[repr(C)]
pub struct EfiTableHeader {
    /// Magic signature identifying the table type.
    pub signature:   u64,
    /// UEFI revision packed as (major << 16 | minor).
    pub revision:    u32,
    /// Total size of the table in bytes, including this header.
    pub header_size: u32,
    /// CRC32 of the whole table with this field zeroed.
    pub crc32:       u32,
    /// Must be zero.
    pub reserved:    u32,
}

// ─────────────────────────────────────────────────────────────────────────────
// EFI GUID
//
// 16-byte globally unique identifier used throughout UEFI to identify
// protocols, configuration table entries, and device paths.
//
// Source: UEFI Spec 2.10 Section 2.3.1 (EFI_GUID)
// Layout: { u32, u16, u16, [u8;8] }
// ─────────────────────────────────────────────────────────────────────────────

#[derive(PartialEq, Eq, Clone, Copy)]
#[repr(C)]
pub struct EfiGuid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

/// ACPI 2.0 RSDP table GUID in the EFI Configuration Table.
///
/// A configuration table entry with this GUID points to the RSDP, which
/// is the root of the entire ACPI table hierarchy.
///
/// Value: {8868e871-e4f1-11d3-bc22-0080c73c8881}
/// Source: UEFI Spec 2.10 Section 4.6 (ACPI 2.0 table GUID)
pub const EFI_ACPI_20_TABLE_GUID: EfiGuid = EfiGuid {
    data1: 0x8868_e871,
    data2: 0xe4f1,
    data3: 0x11d3,
    data4: [0xbc, 0x22, 0x00, 0x80, 0xc7, 0x3c, 0x88, 0x81],
};

// ─────────────────────────────────────────────────────────────────────────────
// EFI Memory Map Types
//
// GetMemoryMap returns an array of EfiMemoryDescriptor, one per physical
// memory region. The descriptor_size return parameter is the actual byte
// stride between entries (may be larger than sizeof to allow vendor fields).
// Iterating MUST use descriptor_size, not sizeof(EfiMemoryDescriptor).
//
// Source: UEFI Spec 2.10 Section 7.2 (Memory Allocation Services)
//         Table 7-1 (Memory Type Definitions)
// ─────────────────────────────────────────────────────────────────────────────

/// EFI memory region type.
/// Source: UEFI Spec 2.10 Table 7-1 (EFI_MEMORY_TYPE values).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum EfiMemoryType {
    Reserved          = 0,
    LoaderCode        = 1,  // hypervisor .text
    LoaderData        = 2,  // hypervisor .data / stack
    BootServicesCode  = 3,
    BootServicesData  = 4,
    RuntimeServicesCode = 5,
    RuntimeServicesData = 6,
    Conventional      = 7,  // usable RAM — AETHER allocates from here
    Unusable          = 8,
    AcpiReclaimable   = 9,  // ACPI tables — usable after ACPI init
    AcpiNvs           = 10, // ACPI NVS — firmware needs this at runtime
    MemoryMappedIo    = 11, // MMIO — do not map into guest conventional RAM
    MemoryMappedIoPortSpace = 12,
    PalCode           = 13,
    PersistentMemory  = 14,
}

impl EfiMemoryType {
    /// Parse a raw u32 from EfiMemoryDescriptor.memory_type.
    /// Returns None if the value does not match any known type.
    #[inline]
    pub const fn from_raw(v: u32) -> Option<Self> {
        match v {
            0  => Some(Self::Reserved),
            1  => Some(Self::LoaderCode),
            2  => Some(Self::LoaderData),
            3  => Some(Self::BootServicesCode),
            4  => Some(Self::BootServicesData),
            5  => Some(Self::RuntimeServicesCode),
            6  => Some(Self::RuntimeServicesData),
            7  => Some(Self::Conventional),
            8  => Some(Self::Unusable),
            9  => Some(Self::AcpiReclaimable),
            10 => Some(Self::AcpiNvs),
            11 => Some(Self::MemoryMappedIo),
            12 => Some(Self::MemoryMappedIoPortSpace),
            13 => Some(Self::PalCode),
            14 => Some(Self::PersistentMemory),
            _  => None,
        }
    }
}

/// One entry in the EFI memory map.
///
/// IMPORTANT: The actual stride between consecutive entries in the firmware's
/// buffer is `descriptor_size` (returned by GetMemoryMap), which MAY be
/// larger than `core::mem::size_of::<EfiMemoryDescriptor>()` due to firmware
/// vendor extensions. Always iterate with `descriptor_size` as the step size.
///
/// Source: UEFI Spec 2.10 Section 7.2, Table 7-2 (EFI_MEMORY_DESCRIPTOR)
#[repr(C)]
pub struct EfiMemoryDescriptor {
    /// Region type — cast to EfiMemoryType with from_raw().
    pub memory_type: u32,
    /// 4 bytes implicit padding (PhysicalStart is 8-byte aligned in C ABI).
    _pad: u32,
    /// First physical address of the region.
    pub physical_start: EfiPhysicalAddress,
    /// Virtual address (only valid after SetVirtualAddressMap — AETHER ignores).
    pub virtual_start: u64,
    /// Number of 4 KiB pages in this region.
    pub number_of_pages: u64,
    /// Memory attribute flags (cacheability, etc.).
    pub attribute: u64,
}

impl EfiMemoryDescriptor {
    /// Size of the region in bytes.
    #[inline]
    pub fn byte_size(&self) -> u64 {
        self.number_of_pages * 4096
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EFI Boot Services Table
//
// The boot services table is a large function pointer table. AETHER uses
// only two functions from it:
//   - GetMemoryMap  at offset  56  (5th function pointer after header)
//   - ExitBootServices at offset 232
//
// All unused slots are modelled as `usize` (opaque function pointer).
// Compile-time assertions below verify these critical offsets.
//
// Source: UEFI Spec 2.10 Section 7.1 (EFI_BOOT_SERVICES table layout)
// ─────────────────────────────────────────────────────────────────────────────

/// Signature of the EFI Boot Services table.
/// "BOOTSERV" = 0x5652_4553_544F_4F42 (little-endian ASCII)
pub const EFI_BOOT_SERVICES_SIGNATURE: u64 = 0x5652_4553_544F_4F42;

#[repr(C)]
pub struct EfiBootServices {
    /// Common 24-byte table header. Signature = EFI_BOOT_SERVICES_SIGNATURE.
    pub header: EfiTableHeader,          // offset   0 (24 bytes)
    // ── Task Priority Services ─────────────────────────────────────────────
    _raise_tpl:    usize,                // offset  24
    _restore_tpl:  usize,                // offset  32
    // ── Memory Allocation Services ────────────────────────────────────────
    _allocate_pages: usize,              // offset  40
    _free_pages:   usize,                // offset  48
    /// GetMemoryMap — returns the current memory map and its "key".
    ///
    /// Signature: GetMemoryMap(map_size, map, map_key, desc_size, desc_version)
    /// The map_key is used in ExitBootServices. If the map changes after
    /// GetMemoryMap but before ExitBootServices, EFI_INVALID_PARAMETER is
    /// returned and both calls must be retried.
    ///
    /// Source: UEFI Spec 2.10 Section 7.2.3
    pub get_memory_map: unsafe extern "efiapi" fn(
        map_size:        *mut usize,
        map:             *mut EfiMemoryDescriptor,
        map_key:         *mut usize,
        descriptor_size: *mut usize,
        descriptor_version: *mut u32,
    ) -> EfiStatus,                      // offset  56
    _allocate_pool:   usize,             // offset  64
    _free_pool:       usize,             // offset  72
    // ── Event & Timer Services ────────────────────────────────────────────
    _create_event:    usize,             // offset  80
    _set_timer:       usize,             // offset  88
    _wait_for_event:  usize,             // offset  96
    _signal_event:    usize,             // offset 104
    _close_event:     usize,             // offset 112
    _check_event:     usize,             // offset 120
    // ── Protocol Handler Services ─────────────────────────────────────────
    _install_protocol_interface:     usize, // offset 128
    _reinstall_protocol_interface:   usize, // offset 136
    _uninstall_protocol_interface:   usize, // offset 144
    /// HandleProtocol — look up a protocol interface on a handle.
    ///
    /// Used by the x86 ESP boot.img reader (`boot_x86_esp::read_esp_file`)
    /// to chain LoadedImage → SimpleFileSystem → root EfiFile. Kept typed
    /// here so callers don't have to `transmute` the raw `usize`.
    ///
    /// Source: UEFI Spec 2.10 Section 7.3 (EFI_BOOT_SERVICES.HandleProtocol)
    pub handle_protocol: unsafe extern "efiapi" fn(
        handle:     EfiHandle,
        protocol:   *const EfiGuid,
        interface:  *mut *mut c_void,
    ) -> EfiStatus,                          // offset 152
    _pc_handle_protocol:             usize, // offset 160  (reserved)
    _register_protocol_notify:       usize, // offset 168
    _locate_handle:                  usize, // offset 176
    _locate_device_path:             usize, // offset 184
    _install_configuration_table:    usize, // offset 192
    // ── Image Services ────────────────────────────────────────────────────
    _load_image:   usize,                // offset 200
    _start_image:  usize,                // offset 208
    _exit_fn:      usize,                // offset 216  ("Exit", renamed to avoid Rust kw)
    _unload_image: usize,                // offset 224
    /// ExitBootServices — take exclusive ownership of all hardware.
    ///
    /// After this call returns EFI_SUCCESS:
    ///   - All firmware boot services are undefined — never call them again
    ///   - The memory map returned by GetMemoryMap is authoritative
    ///   - Firmware event timers have stopped
    ///   - AETHER owns the machine
    ///
    /// Call this with the `map_key` returned by the most recent GetMemoryMap.
    /// If the map changed, returns EFI_INVALID_PARAMETER → must retry.
    ///
    /// Source: UEFI Spec 2.10 Section 7.4.6
    pub exit_boot_services: unsafe extern "efiapi" fn(
        image_handle: EfiHandle,
        map_key:      usize,
    ) -> EfiStatus,                      // offset 232
}

// ─────────────────────────────────────────────────────────────────────────────
// EFI Configuration Table entry
//
// EfiSystemTable.configuration_table points to an array of these. AETHER
// scans the array to find the ACPI RSDP (identified by EFI_ACPI_20_TABLE_GUID).
//
// Source: UEFI Spec 2.10 Section 4.6 (EFI_CONFIGURATION_TABLE)
// ─────────────────────────────────────────────────────────────────────────────

#[repr(C)]
pub struct EfiConfigurationTable {
    /// Identifies what vendor_table points to.
    pub vendor_guid:  EfiGuid,
    /// Physical address of the described table.
    pub vendor_table: *const c_void,
}

// ─────────────────────────────────────────────────────────────────────────────
// EFI System Table
//
// The root of everything the firmware exposes. Passed as the second argument
// to efi_main(). AETHER casts the raw *const c_void from efi_main to this type.
//
// Source: UEFI Spec 2.10 Section 4.3 (EFI_SYSTEM_TABLE)
//
// Field offsets on 64-bit ARM (verified by compile-time assertions below):
//   boot_services       at offset  96
//   configuration_table at offset 112
// ─────────────────────────────────────────────────────────────────────────────

#[repr(C)]
pub struct EfiSystemTable {
    /// Common 24-byte table header.
    pub header: EfiTableHeader,           // offset   0 (24 bytes)
    /// Null-terminated UCS-2 string identifying the firmware vendor.
    pub firmware_vendor: *const u16,      // offset  24
    /// Firmware revision packed as (major << 16 | minor).
    pub firmware_revision: u32,           // offset  32
    /// Alignment padding — PhysicalStart follows at 8-byte boundary.
    _pad: u32,                            // offset  36
    /// Handle for the active console input device.
    pub console_in_handle: EfiHandle,     // offset  40
    _con_in: usize,                       // offset  48
    /// Handle for the active console output device.
    pub console_out_handle: EfiHandle,    // offset  56
    _con_out: usize,                      // offset  64
    /// Handle for the standard error device.
    pub std_err_handle: EfiHandle,        // offset  72
    _std_err: usize,                      // offset  80
    /// Pointer to the EFI Runtime Services Table (used after boot).
    _runtime_services: usize,             // offset  88
    /// Pointer to the EFI Boot Services Table.
    /// AETHER uses this to call GetMemoryMap and ExitBootServices.
    pub boot_services: *const EfiBootServices, // offset  96
    /// Number of entries in configuration_table.
    pub number_of_table_entries: usize,   // offset 104
    /// Array of EFI configuration tables (ACPI RSDP lives here).
    pub configuration_table: *const EfiConfigurationTable, // offset 112
}

// ─────────────────────────────────────────────────────────────────────────────
// Static memory map buffer
//
// GetMemoryMap needs a caller-allocated buffer. AETHER uses a static buffer
// rather than the UEFI allocator because:
//   1. We don't want to allocate from UEFI pool (would create a new map entry)
//   2. After ExitBootServices the allocator is gone anyway
//
// Buffer sizing:
//   Typical ARM64 laptop memory map: 80–200 entries
//   EFI descriptor worst-case size:  56 bytes (40 standard + 16 vendor)
//   Buffer = 512 × 56 = 28 KiB  →  comfortably fits any real machine
//
// Safety: accessed only during single-threaded early boot, before any other
// CPU cores are started and before any interrupts are unmasked.
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum supported byte size of the EFI memory map buffer.
pub const MAX_MEMORY_MAP_BYTES: usize = 512 * 56; // 28 KiB

// Safety: Accessed only from single-threaded boot code before APs start.
static mut EFI_MEMORY_MAP_BUFFER: [u8; MAX_MEMORY_MAP_BYTES] = [0u8; MAX_MEMORY_MAP_BYTES];

// ─────────────────────────────────────────────────────────────────────────────
// AETHER's parsed memory map
//
// After ExitBootServices, AETHER converts the EFI memory map into its own
// compact representation. Up to MAX_MEMORY_REGIONS regions are tracked.
// The rest are discarded as RESERVED.
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum number of memory regions AETHER tracks after boot.
pub const MAX_MEMORY_REGIONS: usize = 64;

/// AETHER's classification of a physical memory region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryRegionKind {
    /// Freely usable RAM — AETHER's pool for Stage 2 page tables and guest RAM.
    Conventional,
    /// Contains ACPI tables. May be reclaimed after ACPI parsing (ch08).
    AcpiReclaimable,
    /// ACPI NVS — firmware requires this memory at runtime. Do not reclaim.
    AcpiNvs,
    /// EFI runtime services code/data. Must remain mapped per UEFI spec.
    RuntimeServices,
    /// Contains AETHER's own code or data (EfiLoaderCode / EfiLoaderData).
    HypervisorImage,
    /// Memory-mapped I/O — device registers. Do not use for RAM.
    MmioRegion,
    /// Reserved by firmware or hardware. Must not be used.
    Reserved,
}

/// A single contiguous physical memory region.
#[derive(Debug, Clone, Copy)]
pub struct MemoryRegion {
    /// First byte of the region (always page-aligned).
    pub base: u64,
    /// Length of the region in bytes (always a multiple of 4 KiB).
    pub size: u64,
    /// How AETHER should treat this region.
    pub kind: MemoryRegionKind,
}

impl MemoryRegion {
    /// Inclusive last byte of the region.
    #[inline]
    pub const fn end_inclusive(&self) -> u64 {
        self.base + self.size - 1
    }

    /// True if `addr` falls within this region.
    #[inline]
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr <= self.end_inclusive()
    }
}

/// AETHER's compact view of physical memory after ExitBootServices.
pub struct MemoryMap {
    regions: [MemoryRegion; MAX_MEMORY_REGIONS],
    count: usize,
}

impl MemoryMap {
    /// Iterate over all recorded regions.
    #[inline]
    pub fn iter(&self) -> core::slice::Iter<'_, MemoryRegion> {
        self.regions[..self.count].iter()
    }

    /// Total bytes of Conventional memory available.
    pub fn total_conventional_bytes(&self) -> u64 {
        self.iter()
            .filter(|r| r.kind == MemoryRegionKind::Conventional)
            .map(|r| r.size)
            .fold(0u64, |acc, s| acc.saturating_add(s))
    }

    /// Find the largest single Conventional region. Used by ch08 to place
    /// Stage 2 page tables in the best-available memory block.
    pub fn largest_conventional(&self) -> Option<MemoryRegion> {
        self.iter()
            .filter(|r| r.kind == MemoryRegionKind::Conventional)
            .copied()
            .max_by_key(|r| r.size)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ACPI table types
//
// AETHER discovers the ACPI table hierarchy from the EFI Configuration Table.
// The chain is:  EFI Config Table → RSDP → XSDT → [MADT, GTDT, IORT, ...]
//
// Skill guide warning: ACPI tables are NOT contiguous in memory. Each has
// its own physical address from the XSDT. Validate Signature and Length
// before trusting any table content.
//
// Source: ACPI Specification 6.5 Section 5.2 (ACPI table structures)
// ─────────────────────────────────────────────────────────────────────────────

/// ACPI v2 RSDP (Root System Description Pointer).
///
/// Located by scanning EFI configuration tables for EFI_ACPI_20_TABLE_GUID.
/// Contains the physical address of the XSDT, which is the root of the
/// ACPI table hierarchy.
///
/// Source: ACPI Spec 6.5 Section 5.2.5.3 (RSDP, Revision 2)
#[repr(C, packed)]
pub struct AcpiRsdp {
    /// "RSD PTR " (8 bytes, no null terminator).
    pub signature: [u8; 8],
    /// One-byte checksum for the first 20 bytes (ACPI 1.0 portion).
    pub checksum:  u8,
    /// OEM identifier string (6 bytes).
    pub oem_id:    [u8; 6],
    /// RSDP version: must be 2 for ACPI 2.0+.
    pub revision:  u8,
    /// Physical address of the RSDT (32-bit, ACPI 1.0 only — use xsdt_address).
    pub rsdt_address: u32,
    /// Total length of this RSDP structure (36 bytes for v2).
    pub length:    u32,
    /// Physical address of the XSDT (64-bit, ACPI 2.0+).
    /// Parse from here — never from rsdt_address on 64-bit systems.
    pub xsdt_address: u64,
    /// Checksum covering the entire v2 RSDP (all 36 bytes).
    pub extended_checksum: u8,
    _reserved: [u8; 3],
}

impl AcpiRsdp {
    /// Expected signature bytes "RSD PTR ".
    pub const SIGNATURE: &'static [u8; 8] = b"RSD PTR ";

    /// True if the RSDP signature is correct and revision >= 2.
    ///
    /// # Safety
    /// `self` must point to mapped, readable memory. The EFI configuration
    /// table entry guarantees this before ExitBootServices.
    #[inline]
    pub fn is_valid(&self) -> bool {
        self.signature == *Self::SIGNATURE && self.revision >= 2
    }
}

/// Common 36-byte header present at the start of every ACPI SDT (System
/// Description Table).
///
/// Source: ACPI Spec 6.5 Section 5.2.6 (ACPI SDT Header fields)
#[repr(C, packed)]
pub struct AcpiSdtHeader {
    /// 4-byte ASCII table signature ("XSDT", "APIC", "GTDT", "IORT", …).
    pub signature:        [u8; 4],
    /// Total length of this table in bytes, including this header.
    pub length:           u32,
    /// Table format revision number.
    pub revision:         u8,
    /// One-byte checksum: sum of all bytes in the table must be 0.
    pub checksum:         u8,
    /// OEM identifier (6 bytes).
    pub oem_id:           [u8; 6],
    /// OEM table identifier (8 bytes).
    pub oem_table_id:     [u8; 8],
    /// OEM revision number.
    pub oem_revision:     u32,
    /// Creator ID (4 bytes, identifies the tool that created the table).
    pub creator_id:       [u8; 4],
    /// Creator revision.
    pub creator_revision: u32,
}

// ── Well-known ACPI table signature constants ──────────────────────────────

/// XSDT: Extended System Description Table — the root table listing all others.
pub const ACPI_XSDT_SIGNATURE: &[u8; 4] = b"XSDT";
/// MADT / APIC: Multiple APIC Description Table — CPU topology and interrupt routing.
pub const ACPI_MADT_SIGNATURE: &[u8; 4] = b"APIC";
/// GTDT: Generic Timer Description Table — ARM architectural timer configuration.
pub const ACPI_GTDT_SIGNATURE: &[u8; 4] = b"GTDT";
/// IORT: I/O Remapping Table — SMMU stream IDs and topology for ch08.
pub const ACPI_IORT_SIGNATURE: &[u8; 4] = b"IORT";
/// DSDT: Differentiated System Description Table — device namespace.
pub const ACPI_DSDT_SIGNATURE: &[u8; 4] = b"DSDT";

// ─────────────────────────────────────────────────────────────────────────────
// Boot context
//
// Captures the UEFI parameters passed to efi_main before they become
// unreachable after ExitBootServices. Drives the entire boot sequence.
// ─────────────────────────────────────────────────────────────────────────────

/// UEFI boot context — populated from the efi_main arguments.
pub struct BootContext {
    /// The UEFI image handle for AETHER (passed as first arg to efi_main).
    pub image_handle: EfiHandle,
    /// Pointer to the EFI System Table (passed as second arg to efi_main).
    pub system_table: *const EfiSystemTable,
}

/// Result of the boot phase — everything AETHER needs after ExitBootServices.
pub struct BootResult {
    /// Parsed physical memory map. Chapter 8 uses this to allocate Stage 2
    /// page tables and partition RAM between AETHER and Android.
    pub memory_map: MemoryMap,
    /// Physical address of the ACPI v2 RSDP, if found in the EFI config table.
    /// Chapter 8 (SMMU) and Chapter 10 (interrupt routing) parse from here.
    pub rsdp_pa: Option<u64>,
}

impl BootContext {
    /// Construct a BootContext from the raw efi_main arguments.
    ///
    /// # Safety
    /// - `image_handle` must be the exact handle passed by UEFI firmware.
    /// - `system_table` must point to a valid, mapped EFI System Table.
    ///   Firmware guarantees this until ExitBootServices is called.
    #[inline]
    pub unsafe fn from_uefi(
        image_handle: EfiHandle,
        system_table: *const EfiSystemTable,
    ) -> Self {
        Self { image_handle, system_table }
    }

    /// Run the full UEFI boot phase:
    ///   1. Capture ACPI RSDP from EFI config table (before exit)
    ///   2. Call ExitBootServices with retry
    ///   3. Parse and return the physical memory map
    ///
    /// After this returns, firmware boot services are gone. Do not call any
    /// EFI function (including through any saved pointers) after this.
    ///
    /// # Safety
    /// Must be called exactly once from the boot CPU before any other CPU
    /// cores are activated. Accesses the static memory map buffer.
    pub unsafe fn run(self) -> BootResult {
        let st = self.system_table;

        // ── Step 1: Capture RSDP before ExitBootServices ──────────────────
        // The UEFI configuration table may be reclaimed by firmware after
        // ExitBootServices. Read it now while firmware pointers are still valid.
        let rsdp_pa = unsafe { find_acpi_rsdp(st) };

        // ── Step 2: ExitBootServices with mandatory retry ──────────────────
        let boot_svc = unsafe { (*st).boot_services };
        let memory_map = unsafe {
            exit_boot_services_with_retry(self.image_handle, boot_svc)
        };

        // ── Firmware boot services are now GONE ───────────────────────────
        // From this point on: `st`, `boot_svc`, and any saved EFI function
        // pointers are undefined. Never dereference them again.

        BootResult { memory_map, rsdp_pa }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ACPI RSDP discovery
//
// Called BEFORE ExitBootServices while the EFI configuration table is valid.
// ─────────────────────────────────────────────────────────────────────────────

/// Search the EFI configuration table for the ACPI 2.0 RSDP.
///
/// Returns the physical address of the RSDP if found, or None if no ACPI
/// 2.0 table is present in the firmware's configuration table.
///
/// # Safety
/// `system_table` must point to a valid, mapped EFI System Table.
/// Must be called before ExitBootServices.
pub unsafe fn find_acpi_rsdp(system_table: *const EfiSystemTable) -> Option<u64> {
    let n = unsafe { (*system_table).number_of_table_entries };
    let tables = unsafe { (*system_table).configuration_table };

    for i in 0..n {
        let entry = unsafe { &*tables.add(i) };
        if entry.vendor_guid == EFI_ACPI_20_TABLE_GUID {
            // Validate the RSDP before returning its address
            let rsdp = entry.vendor_table as *const AcpiRsdp;
            if unsafe { (*rsdp).is_valid() } {
                return Some(entry.vendor_table as u64);
            }
        }
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// ExitBootServices with mandatory retry
//
// The skill guide explicitly identifies this as a common AI failure point:
// Claude generates single-call sequences that don't retry on
// EFI_INVALID_PARAMETER. This implementation is correct: both GetMemoryMap
// and ExitBootServices are re-issued in a loop until exit succeeds.
//
// The retry is required because any firmware allocation or deallocation
// (including allocations triggered by GetMemoryMap itself) changes the map
// key, making the previous key stale.
//
// Source: UEFI Spec 2.10 Section 7.4.6 (ExitBootServices Return Codes)
// Reference: linux-ref/drivers/firmware/efi/libstub/arm64-stub.c
// ─────────────────────────────────────────────────────────────────────────────

/// Call GetMemoryMap + ExitBootServices, retrying until exit succeeds.
///
/// Returns AETHER's parsed compact memory map.
///
/// # Safety
/// - `image_handle` must be AETHER's own UEFI image handle.
/// - `boot_services` must point to a valid EFI Boot Services table.
/// - Accesses the global `EFI_MEMORY_MAP_BUFFER` — single-threaded boot only.
/// - After this returns, the boot services table is invalid. Never call it again.
pub unsafe fn exit_boot_services_with_retry(
    image_handle: EfiHandle,
    boot_services: *const EfiBootServices,
) -> MemoryMap {
    loop {
        // Buffer capacity for this attempt.
        let mut map_size: usize = MAX_MEMORY_MAP_BYTES;
        let mut map_key: usize = 0;
        let mut desc_size: usize = 0;
        let mut desc_version: u32 = 0;

        // ── Call 1: GetMemoryMap ───────────────────────────────────────────
        // Use addr_of_mut! to get a raw pointer without creating a reference
        // to the static mut — required by Rust 2024 edition.
        // addr_of_mut! itself is safe; the actual write happens inside the
        // EFI call below which is already inside an unsafe block.
        let buf_ptr =
            core::ptr::addr_of_mut!(EFI_MEMORY_MAP_BUFFER) as *mut EfiMemoryDescriptor;

        let status = unsafe {
            ((*boot_services).get_memory_map)(
                &mut map_size,
                buf_ptr,
                &mut map_key,
                &mut desc_size,
                &mut desc_version,
            )
        };

        if status == EFI_BUFFER_TOO_SMALL {
            // Static buffer exhausted — machine has more memory regions than
            // MAX_MEMORY_MAP_BYTES / desc_size. This should never happen on
            // a real machine (512 entries is well over any known ARM64 SoC).
            halt();
        }

        if status != EFI_SUCCESS {
            // Any other GetMemoryMap failure is unrecoverable at this stage.
            halt();
        }

        // desc_size must be >= size_of::<EfiMemoryDescriptor>(). If firmware
        // returns something smaller, the table layout is corrupt.
        if desc_size < core::mem::size_of::<EfiMemoryDescriptor>() {
            halt();
        }

        // ── Call 2: ExitBootServices ───────────────────────────────────────
        let exit_status = unsafe {
            ((*boot_services).exit_boot_services)(image_handle, map_key)
        };

        if exit_status == EFI_SUCCESS {
            // ── SUCCESS: parse the now-final memory map ────────────────────
            // map_size was updated by GetMemoryMap to the number of bytes
            // actually written into the buffer.
            return unsafe { parse_memory_map(map_size, desc_size) };
        }

        if exit_status == EFI_INVALID_PARAMETER {
            // Map key is stale — the map changed between our GetMemoryMap call
            // and ExitBootServices. Loop back and try again with a fresh key.
            // This is the mandatory retry path documented in the UEFI spec.
            continue;
        }

        // Any other exit_boot_services error (EFI_NOT_FOUND, etc.) is fatal.
        halt();
    }
}

/// Parse the EFI memory map buffer into AETHER's compact MemoryMap.
///
/// `map_bytes` is the number of valid bytes written by GetMemoryMap.
/// `desc_stride` is the byte stride between consecutive descriptors.
///
/// # Safety
/// The global `EFI_MEMORY_MAP_BUFFER` must contain the data written by the
/// most recent successful GetMemoryMap call. Only call after ExitBootServices
/// has returned EFI_SUCCESS (the buffer won't change after that).
unsafe fn parse_memory_map(map_bytes: usize, desc_stride: usize) -> MemoryMap {
    let mut regions = [MemoryRegion {
        base: 0,
        size: 0,
        kind: MemoryRegionKind::Reserved,
    }; MAX_MEMORY_REGIONS];
    let mut count = 0usize;

    let n_entries = map_bytes / desc_stride;
    // addr_of! gives a raw pointer without a reference — required by Rust 2024.
    let buf_ptr = core::ptr::addr_of!(EFI_MEMORY_MAP_BUFFER) as *const u8;

    for i in 0..n_entries {
        if count >= MAX_MEMORY_REGIONS {
            break; // Table full — remaining regions are implicitly Reserved
        }

        // Safety: i * desc_stride < map_bytes (loop invariant), and
        // EFI_MEMORY_MAP_BUFFER is MAX_MEMORY_MAP_BYTES bytes. GetMemoryMap
        // wrote map_bytes bytes into it.
        let desc = unsafe {
            &*(buf_ptr.add(i * desc_stride) as *const EfiMemoryDescriptor)
        };

        let kind = match EfiMemoryType::from_raw(desc.memory_type) {
            Some(EfiMemoryType::Conventional)        => MemoryRegionKind::Conventional,
            Some(EfiMemoryType::BootServicesCode)    => MemoryRegionKind::Conventional,
            Some(EfiMemoryType::BootServicesData)    => MemoryRegionKind::Conventional,
            Some(EfiMemoryType::AcpiReclaimable)     => MemoryRegionKind::AcpiReclaimable,
            Some(EfiMemoryType::AcpiNvs)             => MemoryRegionKind::AcpiNvs,
            Some(EfiMemoryType::RuntimeServicesCode) => MemoryRegionKind::RuntimeServices,
            Some(EfiMemoryType::RuntimeServicesData) => MemoryRegionKind::RuntimeServices,
            Some(EfiMemoryType::LoaderCode)          => MemoryRegionKind::HypervisorImage,
            Some(EfiMemoryType::LoaderData)          => MemoryRegionKind::HypervisorImage,
            Some(EfiMemoryType::MemoryMappedIo)      => MemoryRegionKind::MmioRegion,
            Some(EfiMemoryType::MemoryMappedIoPortSpace) => MemoryRegionKind::MmioRegion,
            // Reserved, Unusable, PalCode, PersistentMemory, unknown → Reserved
            _ => MemoryRegionKind::Reserved,
        };

        regions[count] = MemoryRegion {
            base: desc.physical_start,
            size: desc.byte_size(),
            kind,
        };
        count += 1;
    }

    MemoryMap { regions, count }
}

// ─────────────────────────────────────────────────────────────────────────────
// ACPI table search
//
// After ExitBootServices, AETHER uses the RSDP address saved earlier to
// navigate the XSDT and find specific tables by their 4-byte signature.
// ─────────────────────────────────────────────────────────────────────────────

/// Walk the XSDT at `xsdt_pa` and return the physical address of the first
/// table whose 4-byte signature matches `sig`.
///
/// Returns None if the XSDT signature is wrong or no match is found.
///
/// # Safety
/// `xsdt_pa` must be the physical address of a valid, mapped XSDT obtained
/// from `AcpiRsdp::xsdt_address`. The XSDT's `Length` field must accurately
/// describe the table size. Both must hold for any real ACPI-compliant firmware.
pub unsafe fn acpi_find_table(xsdt_pa: u64, sig: &[u8; 4]) -> Option<u64> {
    let header = xsdt_pa as *const AcpiSdtHeader;

    // Validate XSDT signature before reading Length.
    if unsafe { (*header).signature } != *ACPI_XSDT_SIGNATURE {
        return None;
    }

    // Length includes the 36-byte header; the rest is u64 physical addresses.
    let total_len = unsafe { (*header).length } as usize;
    if total_len < core::mem::size_of::<AcpiSdtHeader>() {
        return None;
    }

    let entry_bytes = total_len - core::mem::size_of::<AcpiSdtHeader>();
    let n_entries   = entry_bytes / 8;  // each entry is a u64 physical address

    // Pointer to the first u64 entry (immediately after the 36-byte header).
    let entries = unsafe {
        (xsdt_pa as *const u8)
            .add(core::mem::size_of::<AcpiSdtHeader>()) as *const u64
    };

    for i in 0..n_entries {
        let entry_pa = unsafe { *entries.add(i) };
        if entry_pa == 0 {
            continue; // Firmware bug: null entry — skip
        }
        let entry_header = entry_pa as *const AcpiSdtHeader;
        if unsafe { (*entry_header).signature } == *sig {
            return Some(entry_pa);
        }
    }

    None
}

// ─────────────────────────────────────────────────────────────────────────────
// Guest launch — ERET to EL1
//
// After AETHER has:
//   1. Parsed the memory map (this module)
//   2. Constructed Stage 2 page tables (ch08)
//   3. Configured interrupt routing (ch10)
//   4. Loaded the guest bootloader into guest memory
//   5. Constructed the device tree blob (ch17)
//
// it executes ERET to transfer execution to the guest.
//
// ARM64 Linux/Android boot protocol (arm64/booting.rst):
//   ELR_EL2   ← physical address of guest kernel entry point
//   SPSR_EL2  ← GUEST_ENTRY_EL1H (EL1h, all interrupts masked)
//   x0        ← physical address of device tree blob (DTB)
//   x1–x3     ← 0 (reserved by the boot protocol)
//
// The guest kernel will unmask interrupts after it has completed its own
// early initialisation. AETHER starts it with all masked so that an
// interrupt cannot fire before the guest's interrupt controller is configured.
// ─────────────────────────────────────────────────────────────────────────────

/// Parameters for transferring control to a guest at EL1.
///
/// Constructed by the boot sequence after Stage 2 tables and interrupt
/// routing are in place (those steps are in later chapters).
pub struct GuestLaunch {
    /// Physical address of the guest's entry point.
    ///
    /// For Android: the first instruction of the Android Linux kernel image
    /// (after the kernel decompressor, if any). This address must be within
    /// the IPA range mapped by AETHER's Stage 2 tables.
    pub entry_pa: u64,

    /// Physical address of the device tree blob (DTB) describing Android's
    /// assigned hardware. Passed to the kernel in x0 per boot protocol.
    ///
    /// The DTB is constructed by AETHER and describes exactly the hardware
    /// partitioned to Android — not the full machine, not the Windows partition.
    pub dtb_pa: u64,
}

impl GuestLaunch {
    /// Transfer execution to EL1 via ERET. This function never returns.
    ///
    /// Writes ELR_EL2 ← entry_pa, SPSR_EL2 ← GUEST_ENTRY_EL1H,
    /// sets x0 = dtb_pa, zeroes x1–x3, then executes ERET.
    ///
    /// # Safety
    /// MUST be called only after:
    ///   1. Stage 2 page tables are fully constructed and VTTBR_EL2 is set
    ///   2. HCR_EL2.VM = 1 (Stage 2 translation is active)
    ///   3. The exception vector table is installed (VBAR_EL2)
    ///   4. The guest bootloader binary is loaded at entry_pa (IPA-mapped)
    ///   5. CPTR_EL2 is configured (FP/SIMD trap state correct for guest)
    ///
    /// Violating any of these preconditions produces undefined behaviour that
    /// typically manifests as a silent hang or a Stage 2 fault loop.
    ///
    /// # Note on SPSR_EL2
    /// GUEST_ENTRY_EL1H masks FIQ, IRQ, SError, and Debug. The guest kernel
    /// is expected to unmask interrupts during its early boot sequence once
    /// its interrupt controller is initialised.
    #[cfg(target_arch = "aarch64")]
    pub unsafe fn eret_to_el1(&self) -> ! {
        unsafe {
            // Write guest entry point into ELR_EL2.
            write_elr_el2(self.entry_pa);

            // Write target PSTATE: EL1h (EL1 with dedicated SP_EL1),
            // all four interrupt mask bits set.
            write_spsr_el2(spsr_el2::GUEST_ENTRY_EL1H);

            // Load DTB address into x0, zero x1–x3, execute ERET.
            // noreturn: the processor switches to EL1 and never comes back
            // to EL2 through this call frame.
            asm!(
                "mov x0, {dtb}",
                "mov x1, xzr",
                "mov x2, xzr",
                "mov x3, xzr",
                "eret",
                dtb = in(reg) self.dtb_pa,
                options(noreturn, nostack)
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Halt on unrecoverable boot error
//
// Called when a fatal condition is detected during the UEFI boot phase —
// for example, if GetMemoryMap returns an unexpected error or if the static
// buffer is too small. There is nothing meaningful AETHER can do at this
// point (no console, no network, firmware boot services unavailable), so
// the only correct behaviour is to stop the CPU.
// ─────────────────────────────────────────────────────────────────────────────

/// Spin the CPU in a tight loop forever. Called on unrecoverable boot errors.
///
/// This is distinct from the panic handler (which also loops) to make the
/// intent explicit in the boot sequence: a `halt()` call is a deliberate
/// terminal state, not an unexpected panic path.
#[inline(never)]
pub fn halt() -> ! {
    loop {}
}

// ─────────────────────────────────────────────────────────────────────────────
// Compile-time assertions
//
// Verifies that AETHER's struct layouts match the EFI and ACPI specifications.
// A wrong offset means AETHER calls the wrong function from the boot services
// table or reads the wrong field from an ACPI header — both are silent and
// catastrophic. Catching these at compile time is essential.
// ─────────────────────────────────────────────────────────────────────────────

const _: () = {
    use core::mem::{offset_of, size_of};

    // ── EFI Boot Services table offsets ───────────────────────────────────
    // Source: UEFI Spec 2.10 Section 7.1, Table 7-3
    assert!(offset_of!(EfiBootServices, get_memory_map)    ==  56,
        "GetMemoryMap must be at offset 56 in EFI_BOOT_SERVICES");
    assert!(offset_of!(EfiBootServices, exit_boot_services) == 232,
        "ExitBootServices must be at offset 232 in EFI_BOOT_SERVICES");

    // ── EFI System Table field offsets ────────────────────────────────────
    // Source: UEFI Spec 2.10 Section 4.3, Table 4-1
    assert!(offset_of!(EfiSystemTable, boot_services)        ==  96,
        "BootServices must be at offset 96 in EFI_SYSTEM_TABLE");
    assert!(offset_of!(EfiSystemTable, number_of_table_entries) == 104,
        "NumberOfTableEntries must be at offset 104 in EFI_SYSTEM_TABLE");
    assert!(offset_of!(EfiSystemTable, configuration_table)  == 112,
        "ConfigurationTable must be at offset 112 in EFI_SYSTEM_TABLE");

    // ── EFI Table Header size ─────────────────────────────────────────────
    assert!(size_of::<EfiTableHeader>() == 24,
        "EFI_TABLE_HEADER must be exactly 24 bytes");

    // ── EFI Memory Descriptor size ────────────────────────────────────────
    // Source: UEFI Spec 2.10 Section 7.2, Table 7-2 (40 bytes base)
    assert!(size_of::<EfiMemoryDescriptor>() == 40,
        "EFI_MEMORY_DESCRIPTOR base size must be 40 bytes");

    // ── ACPI RSDP size (v2 = 36 bytes) ───────────────────────────────────
    // Source: ACPI Spec 6.5 Section 5.2.5.3
    assert!(size_of::<AcpiRsdp>() == 36,
        "ACPI RSDP v2 must be exactly 36 bytes");

    // ── ACPI SDT header size (36 bytes — same as RSDP coincidentally) ─────
    // Source: ACPI Spec 6.5 Section 5.2.6
    assert!(size_of::<AcpiSdtHeader>() == 36,
        "ACPI SDT header must be exactly 36 bytes");

    // ── EFI GUID size ─────────────────────────────────────────────────────
    assert!(size_of::<EfiGuid>() == 16,
        "EFI_GUID must be exactly 16 bytes");
};
