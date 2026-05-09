// ch18: The Windows ACPI Description
//
// AETHER constructs a complete ACPI table set for the Windows partition before
// ERETing to the Windows UEFI loader. Windows discovers all hardware through
// the table chain rooted at the RSDP — there is no device tree, no second
// hardware description path. Every device Windows sees, every CPU core
// Windows uses, every interrupt Windows handles is described in these tables.
//
// ── Table Chain (ACPI Spec §5.2) ─────────────────────────────────────────────
//
//   EFI Configuration Table (Windows partition's UEFI)
//      → RSDP (Root System Description Pointer, 36 bytes, signature "RSD PTR ")
//          → XSDT (Extended System Description Table, signature "XSDT")
//              → array of u64 physical addresses, each pointing to a named table:
//                  • FACP (FADT — Fixed ACPI Description Table)
//                  • APIC (MADT — Multiple APIC Description Table; ARM GIC entries)
//                  • GTDT (Generic Timer Description Table — ARM arch timer)
//                  • IORT (I/O Remapping Table — SMMU topology)
//
// ── ARM-Specific Tables (Server Base Boot Requirements DEN0044) ──────────────
//
//   MADT for ARM uses GIC entry types, NOT x86 LAPIC/IOAPIC types:
//     Type 0x0B GICC  — one per logical processor (80 bytes per entry)
//     Type 0x0C GICD  — one per system, contains GIC version (24 bytes)
//     Type 0x0E GICR  — one per Redistributor range (16 bytes)
//     Type 0x0F GIC ITS — Interrupt Translation Service for MSI (20 bytes)
//
//   GTDT describes the ARM architectural timer interrupts (PPI range 16–31).
//   Without GTDT, Windows fails timer init and freezes during boot.
//
//   IORT describes the SMMU and which DMA masters route through it. Windows
//   uses IORT to configure its IOMMU driver and Virtualization Based Security.
//
// ── Checksum Rule (ACPI Spec §5.2.6) ─────────────────────────────────────────
//
//   For every ACPI table, the sum of all bytes (including the checksum byte
//   itself) must equal zero modulo 256. Windows refuses tables with bad
//   checksums. AETHER computes and writes the checksum AFTER the table is
//   fully constructed.
//
// ── Hardware-Reduced ACPI ────────────────────────────────────────────────────
//
//   Windows-on-ARM uses hardware-reduced ACPI mode (FADT.Flags bit 20 set).
//   This disables legacy PC hardware references (PIC, PIT, RTC CMOS, SMI)
//   that have no equivalent on ARM. AETHER's FADT must set this bit; without
//   it, Windows tries to access legacy hardware that does not exist.
//
// ── No std, No Alloc ─────────────────────────────────────────────────────────
//
//   Tables are built into caller-provided byte buffers. The caller sizes the
//   buffer based on `*::size(...)` helpers. All multi-byte fields are written
//   via `to_le_bytes()` to avoid alignment faults on ARM.
//
// References:
//   ACPI Specification 6.5 — uefi.org
//   ARM SBBR (Server Base Boot Requirements) DEN0044 — arm.com
//   EDK2 ArmVirtPkg/AcpiTables — github.com/tianocore/edk2 (reference impl)
//   linux-ref/drivers/acpi/arm64/ — Linux ARM ACPI parser (consumer reference)
//   linux-ref/drivers/irqchip/irq-gic-v3.c — GIC version + entry interpretation

use crate::partition::GuestId;

// ─────────────────────────────────────────────────────────────────────────────
// Error type
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcpiError {
    /// Buffer is too small to hold the requested table.
    BufferTooSmall,
    /// Length field in the header does not match actual bytes written.
    LengthMismatch,
    /// Checksum verification failed: sum of bytes mod 256 != 0.
    ChecksumInvalid,
    /// Signature in the header does not match the expected 4 ASCII characters.
    SignatureInvalid,
    /// More entries requested than the table or builder can hold.
    TooManyEntries,
    /// GIC version field is invalid (must be 1, 2, 3, or 4).
    InvalidGicVersion,
    /// Timer interrupt GSIV is outside the PPI range (16–31).
    InvalidTimerInterrupt,
    /// XSDT address array has a NULL entry.
    NullTableAddress,
}

// ─────────────────────────────────────────────────────────────────────────────
// Constants — table signatures and version revisions
//
// Every signature is exactly 4 ASCII characters. Verified against ACPI Spec
// 6.5 §5.2.6 (System Description Tables) and SBBR DEN0044 §C.
// ─────────────────────────────────────────────────────────────────────────────

pub mod sig {
    /// XSDT — Extended System Description Table (root of the table list).
    pub const XSDT: &[u8; 4] = b"XSDT";
    /// APIC — Multiple APIC Description Table (called MADT for ARM).
    pub const MADT: &[u8; 4] = b"APIC";
    /// GTDT — Generic Timer Description Table (ARM architectural timer).
    pub const GTDT: &[u8; 4] = b"GTDT";
    /// IORT — I/O Remapping Table (ARM SMMU topology).
    pub const IORT: &[u8; 4] = b"IORT";
    /// FACP — Fixed ACPI Description Table (FADT).
    pub const FADT: &[u8; 4] = b"FACP";
}

/// RSDP signature — exactly 8 ASCII chars per ACPI Spec §5.2.5.3.
pub const RSDP_SIGNATURE: &[u8; 8] = b"RSD PTR ";

/// Table revision numbers — ACPI Spec 6.5 §5.2 / SBBR DEN0044.
pub mod revision {
    pub const RSDP_V2: u8 = 2;
    pub const XSDT: u8 = 1;
    pub const MADT: u8 = 5; // ACPI 6.5 MADT revision
    pub const GTDT: u8 = 3; // ACPI 6.5 GTDT revision
    pub const IORT: u8 = 6; // IORT specification revision E
    pub const FADT: u8 = 6; // ACPI 6.x FADT revision
}

/// MADT entry type codes — ACPI Spec §5.2.12 + SBBR (ARM-specific entries).
pub mod madt_entry {
    /// GIC CPU Interface (GICC) — type 0x0B, length 80.
    pub const GICC: u8 = 0x0B;
    /// GIC Distributor (GICD) — type 0x0C, length 24.
    pub const GICD: u8 = 0x0C;
    /// GIC MSI Frame (GICv2m) — type 0x0D, length 24. AETHER does not use this.
    pub const GIC_MSI_FRAME: u8 = 0x0D;
    /// GIC Redistributor range (GICR) — type 0x0E, length 16.
    pub const GICR: u8 = 0x0E;
    /// GIC Interrupt Translation Service (ITS) — type 0x0F, length 20.
    pub const GIC_ITS: u8 = 0x0F;
}

/// GIC architecture version field used in GICD entry.
pub mod gic_version {
    pub const V1: u8 = 1;
    pub const V2: u8 = 2;
    pub const V3: u8 = 3;
    pub const V4: u8 = 4;
}

/// FADT.Flags bit positions (ACPI Spec §5.2.9.3, Table 5.10).
pub mod fadt_flag {
    /// HARDWARE_REDUCED_ACPI — set for ARM platforms.
    /// Disables legacy x86 hardware (PIC, RTC CMOS, etc.).
    pub const HW_REDUCED_ACPI: u32 = 1 << 20;
    /// LOW_POWER_S0_IDLE_CAPABLE — modern standby support.
    pub const LOW_POWER_S0_IDLE: u32 = 1 << 21;
}

/// ARM PSCI control bit set in FADT.ArmBootArchFlags (ACPI Spec §5.2.9.4).
pub mod arm_boot_arch {
    /// PSCI_COMPLIANT bit — Windows uses PSCI for power management.
    pub const PSCI_COMPLIANT: u16 = 1 << 0;
    /// PSCI_USE_HVC bit — PSCI calls go via HVC, not SMC.
    pub const PSCI_USE_HVC: u16 = 1 << 1;
}

/// ARM Generic Timer flags (GTDT timer flag byte, ACPI Spec §5.2.24).
pub mod timer_flag {
    /// Trigger mode: 0 = level, 1 = edge.
    pub const EDGE_TRIGGERED: u32 = 1 << 0;
    /// Polarity: 0 = active high, 1 = active low.
    pub const ACTIVE_LOW: u32 = 1 << 1;
    /// Always-on: timer is functional even in deepest sleep state.
    pub const ALWAYS_ON: u32 = 1 << 2;
}

// ─────────────────────────────────────────────────────────────────────────────
// Table sizes (compile-time constants, used for buffer sizing and validation)
// ─────────────────────────────────────────────────────────────────────────────

pub const ACPI_HEADER_LEN: usize = 36;
pub const RSDP_V2_LEN: usize = 36;
pub const MADT_GICC_ENTRY_LEN: usize = 80;
pub const MADT_GICD_ENTRY_LEN: usize = 24;
pub const MADT_GICR_ENTRY_LEN: usize = 16;
pub const MADT_GIC_ITS_ENTRY_LEN: usize = 20;
/// MADT body before entries = 4 (LocalInterruptControllerAddress) + 4 (Flags).
pub const MADT_FIXED_BODY_LEN: usize = 8;
/// GTDT body length (no platform timers) per ACPI Spec §5.2.24:
///   CntControlBase(8) + Reserved(4) + 4×(GSIV(4)+Flags(4)) +
///   CntReadBase(8) + PlatformTimerCount(4) + PlatformTimerOffset(4) = 60.
pub const GTDT_FIXED_BODY_LEN: usize = 60;
/// FADT body length = 244 bytes for revision 6 (ACPI 6.x).
pub const FADT_BODY_LEN: usize = 244;

// ─────────────────────────────────────────────────────────────────────────────
// Common header + checksum
//
// Every ACPI table starts with this 36-byte header (ACPI Spec §5.2.6, Table 5-30).
// The checksum is the last byte to be computed: it is the value such that the
// sum of ALL bytes in the table (including the checksum byte) equals 0 mod 256.
// ─────────────────────────────────────────────────────────────────────────────

/// Compute the 8-bit ACPI checksum over a byte range.
///
/// Returns the value to write into the checksum byte such that the sum of
/// all bytes (including the checksum byte itself) is zero modulo 256.
pub fn compute_checksum(bytes: &[u8]) -> u8 {
    let sum = bytes.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
    0u8.wrapping_sub(sum)
}

/// Verify that a fully-built table's checksum is correct.
///
/// Returns Ok if the sum of all bytes is 0 mod 256.
pub fn verify_checksum(bytes: &[u8]) -> Result<(), AcpiError> {
    let sum = bytes.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
    if sum == 0 {
        Ok(())
    } else {
        Err(AcpiError::ChecksumInvalid)
    }
}

/// Write the 36-byte ACPI common header into `buf` at offset 0.
///
/// `length` is the total table length INCLUDING the header. The checksum byte
/// is left as zero — call `finalize_table()` after writing the table body.
pub fn write_header(
    buf: &mut [u8],
    signature: &[u8; 4],
    length: u32,
    revision: u8,
    oem_id: &[u8; 6],
    oem_table_id: &[u8; 8],
    oem_revision: u32,
) -> Result<(), AcpiError> {
    if buf.len() < ACPI_HEADER_LEN {
        return Err(AcpiError::BufferTooSmall);
    }
    buf[0..4].copy_from_slice(signature);
    buf[4..8].copy_from_slice(&length.to_le_bytes());
    buf[8] = revision;
    buf[9] = 0; // checksum placeholder
    buf[10..16].copy_from_slice(oem_id);
    buf[16..24].copy_from_slice(oem_table_id);
    buf[24..28].copy_from_slice(&oem_revision.to_le_bytes());
    buf[28..32].copy_from_slice(b"AETH"); // Creator ID
    buf[32..36].copy_from_slice(&1u32.to_le_bytes()); // Creator Revision
    Ok(())
}

/// Compute and write the checksum for a fully-built table.
///
/// `total_length` must equal the value written into the Length field.
/// Verifies length consistency and writes byte 9 with the correct checksum.
pub fn finalize_table(buf: &mut [u8], total_length: usize) -> Result<(), AcpiError> {
    if buf.len() < total_length || total_length < ACPI_HEADER_LEN {
        return Err(AcpiError::BufferTooSmall);
    }
    // Read back the Length field and confirm it matches total_length.
    let length_field = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]) as usize;
    if length_field != total_length {
        return Err(AcpiError::LengthMismatch);
    }
    // Zero the checksum byte before computing.
    buf[9] = 0;
    let sum = buf[..total_length]
        .iter()
        .fold(0u8, |acc, &b| acc.wrapping_add(b));
    buf[9] = 0u8.wrapping_sub(sum);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// RSDP — Root System Description Pointer (ACPI Spec §5.2.5.3)
//
// 36-byte structure with TWO checksums:
//   bytes [0..20]  → first checksum at byte 8 (ACPI 1.0 compatibility)
//   bytes [0..36]  → extended checksum at byte 32
// Both must independently sum to 0 mod 256.
// ─────────────────────────────────────────────────────────────────────────────

/// Build the v2 RSDP into a 36-byte buffer.
///
/// `xsdt_pa` is the physical address of the XSDT in the Windows partition's
/// address space. Both checksums (v1 at offset 8, extended at offset 32) are
/// computed and written.
pub fn build_rsdp(
    buf: &mut [u8],
    oem_id: &[u8; 6],
    xsdt_pa: u64,
) -> Result<(), AcpiError> {
    if buf.len() < RSDP_V2_LEN {
        return Err(AcpiError::BufferTooSmall);
    }
    // Zero the buffer to ensure reserved bytes are 0.
    for b in buf[..RSDP_V2_LEN].iter_mut() {
        *b = 0;
    }
    buf[0..8].copy_from_slice(RSDP_SIGNATURE);
    // buf[8] = v1 checksum placeholder
    buf[9..15].copy_from_slice(oem_id);
    buf[15] = revision::RSDP_V2;
    // buf[16..20] = RsdtAddress (legacy 32-bit; AETHER uses XSDT only, so 0)
    buf[20..24].copy_from_slice(&(RSDP_V2_LEN as u32).to_le_bytes()); // Length
    buf[24..32].copy_from_slice(&xsdt_pa.to_le_bytes());
    // buf[32] = extended checksum placeholder
    // buf[33..36] = reserved (already 0)

    // V1 checksum covers bytes [0..20] — sum must be 0 mod 256.
    let v1_sum = buf[0..20].iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
    buf[8] = 0u8.wrapping_sub(v1_sum);

    // Extended checksum covers all 36 bytes — sum must be 0 mod 256.
    let v2_sum = buf[0..RSDP_V2_LEN]
        .iter()
        .fold(0u8, |acc, &b| acc.wrapping_add(b));
    buf[32] = 0u8.wrapping_sub(v2_sum);
    Ok(())
}

/// Verify both checksums of an RSDP buffer.
pub fn verify_rsdp(buf: &[u8]) -> Result<(), AcpiError> {
    if buf.len() < RSDP_V2_LEN {
        return Err(AcpiError::BufferTooSmall);
    }
    if &buf[0..8] != RSDP_SIGNATURE {
        return Err(AcpiError::SignatureInvalid);
    }
    let v1_sum = buf[0..20].iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
    if v1_sum != 0 {
        return Err(AcpiError::ChecksumInvalid);
    }
    let v2_sum = buf[0..RSDP_V2_LEN]
        .iter()
        .fold(0u8, |acc, &b| acc.wrapping_add(b));
    if v2_sum != 0 {
        return Err(AcpiError::ChecksumInvalid);
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// XSDT — Extended System Description Table (ACPI Spec §5.2.8)
//
// Layout: 36-byte common header + N × u64 table addresses.
// Length field = 36 + (n_tables × 8).
// ─────────────────────────────────────────────────────────────────────────────

/// Compute the byte size of an XSDT containing `n_tables` entries.
pub const fn xsdt_size(n_tables: usize) -> usize {
    ACPI_HEADER_LEN + n_tables * 8
}

/// Build the XSDT.
///
/// Each entry in `table_addrs` is the physical address of a downstream ACPI
/// table (FADT, MADT, GTDT, IORT, …). All addresses must be non-zero.
pub fn build_xsdt(
    buf: &mut [u8],
    oem_id: &[u8; 6],
    oem_table_id: &[u8; 8],
    oem_revision: u32,
    table_addrs: &[u64],
) -> Result<usize, AcpiError> {
    let total = xsdt_size(table_addrs.len());
    if buf.len() < total {
        return Err(AcpiError::BufferTooSmall);
    }
    for &addr in table_addrs {
        if addr == 0 {
            return Err(AcpiError::NullTableAddress);
        }
    }
    write_header(
        buf,
        sig::XSDT,
        total as u32,
        revision::XSDT,
        oem_id,
        oem_table_id,
        oem_revision,
    )?;
    let mut off = ACPI_HEADER_LEN;
    for &addr in table_addrs {
        buf[off..off + 8].copy_from_slice(&addr.to_le_bytes());
        off += 8;
    }
    finalize_table(buf, total)?;
    Ok(total)
}

// ─────────────────────────────────────────────────────────────────────────────
// MADT — Multiple APIC Description Table for ARM (ACPI Spec §5.2.12 + SBBR)
//
// Header (36 bytes) + Body (8 bytes: LocalInterruptControllerAddress + Flags)
// + variable-length array of GIC entries.
// ─────────────────────────────────────────────────────────────────────────────

/// One GIC CPU Interface entry — describes one logical processor.
#[derive(Clone, Copy, Debug)]
pub struct GiccEntry {
    /// CPU Interface Number (per-core unique ID).
    pub cpu_interface_number: u32,
    /// ACPI Processor UID — must match the UID in the DSDT.
    pub acpi_processor_uid: u32,
    /// Flags (bit 0 = enabled).
    pub flags: u32,
    /// Performance Interrupt GSIV (PMU IRQ).
    pub performance_interrupt: u32,
    /// Parked Address (0 if not used).
    pub parked_address: u64,
    /// GICR base address for this CPU (GICv3+; per-core 128 KiB region).
    pub gicr_base_address: u64,
    /// MPIDR_EL1 affinity bits (matches ch09 Mpidr::affinity_value()).
    pub mpidr: u64,
    /// Maintenance interrupt GSIV (typically PPI 25).
    pub vgic_maintenance_interrupt: u32,
}

impl GiccEntry {
    /// Write this GICC entry into `buf` at offset 0. Returns 80 (entry size).
    pub fn write(&self, buf: &mut [u8]) -> Result<usize, AcpiError> {
        if buf.len() < MADT_GICC_ENTRY_LEN {
            return Err(AcpiError::BufferTooSmall);
        }
        // Zero the entry first to ensure all reserved/unused fields are 0.
        for b in buf[..MADT_GICC_ENTRY_LEN].iter_mut() {
            *b = 0;
        }
        buf[0] = madt_entry::GICC;
        buf[1] = MADT_GICC_ENTRY_LEN as u8;
        // buf[2..4] = reserved
        buf[4..8].copy_from_slice(&self.cpu_interface_number.to_le_bytes());
        buf[8..12].copy_from_slice(&self.acpi_processor_uid.to_le_bytes());
        buf[12..16].copy_from_slice(&self.flags.to_le_bytes());
        // buf[16..20] = ParkingProtocolVersion (0)
        buf[20..24].copy_from_slice(&self.performance_interrupt.to_le_bytes());
        buf[24..32].copy_from_slice(&self.parked_address.to_le_bytes());
        // buf[32..40] = PhysicalBaseAddress (GICv2 CPU interface; 0 on GICv3)
        // buf[40..48] = GICV (GICv2 only; 0 on GICv3)
        // buf[48..56] = GICH (GICv2 only; 0 on GICv3)
        buf[56..60].copy_from_slice(&self.vgic_maintenance_interrupt.to_le_bytes());
        buf[60..68].copy_from_slice(&self.gicr_base_address.to_le_bytes());
        buf[68..76].copy_from_slice(&self.mpidr.to_le_bytes());
        // buf[76] = ProcessorPowerEfficiencyClass (0)
        // buf[77] = reserved
        // buf[78..80] = SPEOverflowInterrupt (0)
        Ok(MADT_GICC_ENTRY_LEN)
    }
}

/// One GIC Distributor entry — describes the global GICD.
#[derive(Clone, Copy, Debug)]
pub struct GicdEntry {
    /// GIC ID (system identifier).
    pub gic_id: u32,
    /// GICD physical base address.
    pub physical_base_address: u64,
    /// GIC architecture version (3 for GICv3 on Snapdragon).
    pub gic_version: u8,
}

impl GicdEntry {
    pub fn write(&self, buf: &mut [u8]) -> Result<usize, AcpiError> {
        if buf.len() < MADT_GICD_ENTRY_LEN {
            return Err(AcpiError::BufferTooSmall);
        }
        if !matches!(
            self.gic_version,
            gic_version::V1 | gic_version::V2 | gic_version::V3 | gic_version::V4
        ) {
            return Err(AcpiError::InvalidGicVersion);
        }
        for b in buf[..MADT_GICD_ENTRY_LEN].iter_mut() {
            *b = 0;
        }
        buf[0] = madt_entry::GICD;
        buf[1] = MADT_GICD_ENTRY_LEN as u8;
        // buf[2..4] = reserved
        buf[4..8].copy_from_slice(&self.gic_id.to_le_bytes());
        buf[8..16].copy_from_slice(&self.physical_base_address.to_le_bytes());
        // buf[16..20] = SystemVectorBase (0)
        buf[20] = self.gic_version;
        // buf[21..24] = reserved
        Ok(MADT_GICD_ENTRY_LEN)
    }
}

/// One GIC Redistributor range entry.
#[derive(Clone, Copy, Debug)]
pub struct GicrEntry {
    /// Discovery Range Base Address (start of the GICR range covering all PEs).
    pub discovery_range_base_address: u64,
    /// Discovery Range Length in bytes (typically 0x20000 per PE).
    pub discovery_range_length: u32,
}

impl GicrEntry {
    pub fn write(&self, buf: &mut [u8]) -> Result<usize, AcpiError> {
        if buf.len() < MADT_GICR_ENTRY_LEN {
            return Err(AcpiError::BufferTooSmall);
        }
        for b in buf[..MADT_GICR_ENTRY_LEN].iter_mut() {
            *b = 0;
        }
        buf[0] = madt_entry::GICR;
        buf[1] = MADT_GICR_ENTRY_LEN as u8;
        // buf[2..4] = reserved
        buf[4..12].copy_from_slice(&self.discovery_range_base_address.to_le_bytes());
        buf[12..16].copy_from_slice(&self.discovery_range_length.to_le_bytes());
        Ok(MADT_GICR_ENTRY_LEN)
    }
}

/// One GIC ITS (Interrupt Translation Service) entry — for MSI support.
#[derive(Clone, Copy, Debug)]
pub struct GicItsEntry {
    /// GIC ITS ID (unique per ITS instance).
    pub its_id: u32,
    /// ITS physical base address (translater base).
    pub physical_base_address: u64,
}

impl GicItsEntry {
    pub fn write(&self, buf: &mut [u8]) -> Result<usize, AcpiError> {
        if buf.len() < MADT_GIC_ITS_ENTRY_LEN {
            return Err(AcpiError::BufferTooSmall);
        }
        for b in buf[..MADT_GIC_ITS_ENTRY_LEN].iter_mut() {
            *b = 0;
        }
        buf[0] = madt_entry::GIC_ITS;
        buf[1] = MADT_GIC_ITS_ENTRY_LEN as u8;
        // buf[2..4] = reserved
        buf[4..8].copy_from_slice(&self.its_id.to_le_bytes());
        buf[8..16].copy_from_slice(&self.physical_base_address.to_le_bytes());
        // buf[16..20] = reserved
        Ok(MADT_GIC_ITS_ENTRY_LEN)
    }
}

/// Compute the byte size of a MADT given counts of each entry type.
pub const fn madt_size(n_gicc: usize, n_gicr: usize, n_its: usize, has_gicd: bool) -> usize {
    ACPI_HEADER_LEN
        + MADT_FIXED_BODY_LEN
        + n_gicc * MADT_GICC_ENTRY_LEN
        + (if has_gicd { MADT_GICD_ENTRY_LEN } else { 0 })
        + n_gicr * MADT_GICR_ENTRY_LEN
        + n_its * MADT_GIC_ITS_ENTRY_LEN
}

/// Build a MADT.
///
/// Layout: header → 8-byte fixed body (LocalInterruptControllerAddress=0,
/// Flags=0) → GICC entries → GICD → GICR entries → GIC ITS entries.
/// Caller pre-computes the buffer size with `madt_size()`.
pub fn build_madt(
    buf: &mut [u8],
    oem_id: &[u8; 6],
    oem_table_id: &[u8; 8],
    oem_revision: u32,
    gicc_entries: &[GiccEntry],
    gicd: &GicdEntry,
    gicr_entries: &[GicrEntry],
    its_entries: &[GicItsEntry],
) -> Result<usize, AcpiError> {
    let total = madt_size(gicc_entries.len(), gicr_entries.len(), its_entries.len(), true);
    if buf.len() < total {
        return Err(AcpiError::BufferTooSmall);
    }
    write_header(
        buf,
        sig::MADT,
        total as u32,
        revision::MADT,
        oem_id,
        oem_table_id,
        oem_revision,
    )?;
    // Fixed body — both fields are 0 on ARM (no x86 LAPIC, no PC/AT 8259).
    for b in buf[ACPI_HEADER_LEN..ACPI_HEADER_LEN + MADT_FIXED_BODY_LEN].iter_mut() {
        *b = 0;
    }
    let mut off = ACPI_HEADER_LEN + MADT_FIXED_BODY_LEN;
    // GICC entries.
    for e in gicc_entries {
        let n = e.write(&mut buf[off..])?;
        off += n;
    }
    // GICD entry.
    {
        let n = gicd.write(&mut buf[off..])?;
        off += n;
    }
    // GICR entries.
    for e in gicr_entries {
        let n = e.write(&mut buf[off..])?;
        off += n;
    }
    // GIC ITS entries.
    for e in its_entries {
        let n = e.write(&mut buf[off..])?;
        off += n;
    }
    if off != total {
        return Err(AcpiError::LengthMismatch);
    }
    finalize_table(buf, total)?;
    Ok(total)
}

// ─────────────────────────────────────────────────────────────────────────────
// GTDT — Generic Timer Description Table (ACPI Spec §5.2.24, SBBR)
//
// Describes the ARM architectural timer interrupts and (optionally) memory-
// mapped timer base addresses.
//
// Body layout (after 36-byte header):
//   [36..44] CntControlBasePhysicalAddress (0xFFFFFFFFFFFFFFFF if not memory-mapped)
//   [44..48] Reserved
//   [48..52] SecureEL1TimerGSIV
//   [52..56] SecureEL1TimerFlags
//   [56..60] NonSecureEL1TimerGSIV
//   [60..64] NonSecureEL1TimerFlags
//   [64..68] VirtualEL1TimerGSIV
//   [68..72] VirtualEL1TimerFlags
//   [72..76] EL2TimerGSIV
//   [76..80] EL2TimerFlags
//   [80..88] CntReadBasePhysicalAddress (0xFFFFFFFFFFFFFFFF if not memory-mapped)
//   [88..92] PlatformTimerCount = 0
//   [92..96] PlatformTimerOffset = 0
// Total: 96 bytes (header 36 + body 60).
// ─────────────────────────────────────────────────────────────────────────────

/// ARM architectural timer interrupt configuration.
///
/// All four interrupt IDs are in the PPI range (16–31) on standard ARM cores.
/// Default Snapdragon X Elite values match the EDK2 ArmVirtPkg defaults.
#[derive(Clone, Copy, Debug)]
pub struct ArmTimerConfig {
    pub secure_el1_gsiv: u32,
    pub secure_el1_flags: u32,
    pub nonsecure_el1_gsiv: u32,
    pub nonsecure_el1_flags: u32,
    pub virtual_el1_gsiv: u32,
    pub virtual_el1_flags: u32,
    pub el2_gsiv: u32,
    pub el2_flags: u32,
}

impl ArmTimerConfig {
    /// Default ARM timer config for ARMv8-A (Snapdragon X Elite, EDK2 ArmVirtPkg).
    pub const DEFAULT: Self = Self {
        secure_el1_gsiv: 29,    // PPI 13
        secure_el1_flags: 0,    // level-triggered, active high
        nonsecure_el1_gsiv: 30, // PPI 14
        nonsecure_el1_flags: 0,
        virtual_el1_gsiv: 27,   // PPI 11
        virtual_el1_flags: 0,
        el2_gsiv: 26,           // PPI 10
        el2_flags: 0,
    };

    /// Validate that all timer GSIVs are in the PPI range (16–31).
    pub fn validate(&self) -> Result<(), AcpiError> {
        for gsiv in [
            self.secure_el1_gsiv,
            self.nonsecure_el1_gsiv,
            self.virtual_el1_gsiv,
            self.el2_gsiv,
        ] {
            if !(16..=31).contains(&gsiv) {
                return Err(AcpiError::InvalidTimerInterrupt);
            }
        }
        Ok(())
    }
}

pub const GTDT_TOTAL_LEN: usize = ACPI_HEADER_LEN + GTDT_FIXED_BODY_LEN;

/// Build the GTDT (no platform timers).
pub fn build_gtdt(
    buf: &mut [u8],
    oem_id: &[u8; 6],
    oem_table_id: &[u8; 8],
    oem_revision: u32,
    timer: &ArmTimerConfig,
) -> Result<usize, AcpiError> {
    timer.validate()?;
    let total = GTDT_TOTAL_LEN;
    if buf.len() < total {
        return Err(AcpiError::BufferTooSmall);
    }
    write_header(
        buf,
        sig::GTDT,
        total as u32,
        revision::GTDT,
        oem_id,
        oem_table_id,
        oem_revision,
    )?;
    // CntControlBasePhysicalAddress = 0xFFFFFFFFFFFFFFFF (no memory-mapped CntCtrl).
    buf[36..44].copy_from_slice(&0xFFFF_FFFF_FFFF_FFFFu64.to_le_bytes());
    // Reserved.
    buf[44..48].copy_from_slice(&0u32.to_le_bytes());
    // Timer GSIV/Flags pairs.
    buf[48..52].copy_from_slice(&timer.secure_el1_gsiv.to_le_bytes());
    buf[52..56].copy_from_slice(&timer.secure_el1_flags.to_le_bytes());
    buf[56..60].copy_from_slice(&timer.nonsecure_el1_gsiv.to_le_bytes());
    buf[60..64].copy_from_slice(&timer.nonsecure_el1_flags.to_le_bytes());
    buf[64..68].copy_from_slice(&timer.virtual_el1_gsiv.to_le_bytes());
    buf[68..72].copy_from_slice(&timer.virtual_el1_flags.to_le_bytes());
    buf[72..76].copy_from_slice(&timer.el2_gsiv.to_le_bytes());
    buf[76..80].copy_from_slice(&timer.el2_flags.to_le_bytes());
    // CntReadBasePhysicalAddress = 0xFFFFFFFFFFFFFFFF (no memory-mapped CntRead).
    buf[80..88].copy_from_slice(&0xFFFF_FFFF_FFFF_FFFFu64.to_le_bytes());
    // PlatformTimerCount = 0; PlatformTimerOffset = 0.
    buf[88..92].copy_from_slice(&0u32.to_le_bytes());
    buf[92..96].copy_from_slice(&0u32.to_le_bytes());
    finalize_table(buf, total)?;
    Ok(total)
}

// ─────────────────────────────────────────────────────────────────────────────
// IORT — I/O Remapping Table (IORT Specification revision E)
//
// Describes the SMMU topology. AETHER's IORT is intentionally minimal: it
// declares one SMMUv3 node and one Root Complex node connected to it, with
// a single ID mapping that covers the PCIe segment.
//
// IORT structure:
//   [36..40]  NumNodes (number of IORT nodes)
//   [40..44]  NodeOffset (offset to first node)
//   [44..48]  Reserved
//   [48..]    Node array
//
// Each node header (16 bytes):
//   [0]    Type (3 = SMMUv3, 2 = Root Complex)
//   [1..3] Length
//   [3]    Revision
//   [4..8] Identifier
//   [8..12] NumIDMappings
//   [12..16] IDArrayOffset
//
// SMMUv3 node body (after 16-byte header) — 68 bytes:
//   BaseAddress, Flags, Reserved, VATOS, Model, Event, PRI, GErr, Sync,
//   Proximity, DeviceIDMappingIndex
//
// Root Complex node body — 36 bytes:
//   CacheCoherent, AllocationHints, Reserved, MemoryAccessFlags, ATSAttribute,
//   PCIESegmentNumber, MemoryAddressSizeLimit, PASIDCapabilities, Flags
//
// This implementation provides a minimal but valid IORT. Production may
// need additional nodes (NamedComponent, PMCG) per actual hardware.
// ─────────────────────────────────────────────────────────────────────────────

pub mod iort_node {
    pub const ITS_GROUP: u8 = 0;
    pub const NAMED_COMPONENT: u8 = 1;
    pub const ROOT_COMPLEX: u8 = 2;
    pub const SMMU_V1_V2: u8 = 3;
    pub const SMMU_V3: u8 = 4;
    pub const PMCG: u8 = 5;
}

/// Minimal SMMUv3 node configuration.
#[derive(Clone, Copy, Debug)]
pub struct SmmuV3Node {
    /// Physical base address of the SMMUv3 register space.
    pub base_address: u64,
    /// Combined event / SYNC / GERR / PRI interrupt GSIV (one shared SPI).
    /// In this minimal config the same GSIV is used for all four.
    pub event_interrupt: u32,
}

/// Minimal Root Complex node configuration.
#[derive(Clone, Copy, Debug)]
pub struct RootComplexNode {
    /// PCIe segment number.
    pub pcie_segment: u32,
    /// True if this RC is cache-coherent with CPU.
    pub cache_coherent: bool,
}

/// IORT total size with 1 SMMUv3 node + 1 Root Complex node.
/// SMMUv3 node = 16 (hdr) + 68 (body) = 84 bytes.
/// RC node = 16 (hdr) + 36 (body) = 52 bytes.
/// IORT body = 12 bytes (NumNodes, NodeOffset, Reserved).
/// Total = 36 + 12 + 84 + 52 = 184 bytes.
pub const IORT_MIN_LEN: usize = 184;

/// Build a minimal IORT with one SMMUv3 + one Root Complex node.
pub fn build_iort(
    buf: &mut [u8],
    oem_id: &[u8; 6],
    oem_table_id: &[u8; 8],
    oem_revision: u32,
    smmu: &SmmuV3Node,
    rc: &RootComplexNode,
) -> Result<usize, AcpiError> {
    let total = IORT_MIN_LEN;
    if buf.len() < total {
        return Err(AcpiError::BufferTooSmall);
    }
    // Zero the table body to ensure all reserved fields are 0.
    for b in buf[ACPI_HEADER_LEN..total].iter_mut() {
        *b = 0;
    }
    write_header(
        buf,
        sig::IORT,
        total as u32,
        revision::IORT,
        oem_id,
        oem_table_id,
        oem_revision,
    )?;
    // IORT body.
    buf[36..40].copy_from_slice(&2u32.to_le_bytes()); // NumNodes = 2
    buf[40..44].copy_from_slice(&48u32.to_le_bytes()); // NodeOffset = 48
    // buf[44..48] = reserved (already 0)

    // ── SMMUv3 node at offset 48, length 84 ──
    let smmu_off = 48;
    let smmu_len: u16 = 84;
    buf[smmu_off] = iort_node::SMMU_V3;
    buf[smmu_off + 1..smmu_off + 3].copy_from_slice(&smmu_len.to_le_bytes());
    buf[smmu_off + 3] = 4; // Revision
    buf[smmu_off + 4..smmu_off + 8].copy_from_slice(&0u32.to_le_bytes()); // Identifier
    buf[smmu_off + 8..smmu_off + 12].copy_from_slice(&0u32.to_le_bytes()); // NumIDMappings
    buf[smmu_off + 12..smmu_off + 16].copy_from_slice(&0u32.to_le_bytes()); // IDArrayOffset
    // SMMUv3-specific body (starts at smmu_off + 16, 68 bytes).
    let smmu_body = smmu_off + 16;
    buf[smmu_body..smmu_body + 8].copy_from_slice(&smmu.base_address.to_le_bytes());
    // Flags (4) + Reserved (4) + VATOS (8) + Model (4) at +8..+28 = 0
    // Event (+28..+32), PRI (+32..+36), GErr (+36..+40), Sync (+40..+44)
    let evt = smmu.event_interrupt.to_le_bytes();
    buf[smmu_body + 28..smmu_body + 32].copy_from_slice(&evt);
    buf[smmu_body + 32..smmu_body + 36].copy_from_slice(&evt);
    buf[smmu_body + 36..smmu_body + 40].copy_from_slice(&evt);
    buf[smmu_body + 40..smmu_body + 44].copy_from_slice(&evt);
    // Proximity (+44..+48), DeviceIDMappingIndex (+48..+52),
    // remaining reserved up to +68 — all 0.

    // ── Root Complex node at offset 132, length 52 ──
    let rc_off = smmu_off + 84; // 48 + 84 = 132
    let rc_len: u16 = 52;
    buf[rc_off] = iort_node::ROOT_COMPLEX;
    buf[rc_off + 1..rc_off + 3].copy_from_slice(&rc_len.to_le_bytes());
    buf[rc_off + 3] = 4; // Revision
    buf[rc_off + 4..rc_off + 8].copy_from_slice(&1u32.to_le_bytes()); // Identifier
    buf[rc_off + 8..rc_off + 12].copy_from_slice(&0u32.to_le_bytes()); // NumIDMappings
    buf[rc_off + 12..rc_off + 16].copy_from_slice(&0u32.to_le_bytes()); // IDArrayOffset
    // RC body starts at rc_off + 16, 36 bytes.
    let rc_body = rc_off + 16;
    let cache_coherent: u32 = if rc.cache_coherent { 1 } else { 0 };
    buf[rc_body..rc_body + 4].copy_from_slice(&cache_coherent.to_le_bytes());
    // AllocationHints (+4), Reserved (+5..+8), MemoryAccessFlags (+8..+9),
    // ATSAttribute (+12..+16) — all 0.
    buf[rc_body + 16..rc_body + 20].copy_from_slice(&rc.pcie_segment.to_le_bytes());
    // MemoryAddressSizeLimit (+20), PASIDCapabilities (+22..+24),
    // Flags (+28..+32) — all 0.

    finalize_table(buf, total)?;
    Ok(total)
}

// ─────────────────────────────────────────────────────────────────────────────
// FADT — Fixed ACPI Description Table (ACPI Spec §5.2.9)
//
// Hardware-reduced ACPI for ARM. AETHER sets FADT.Flags bit 20 (HW_REDUCED_ACPI)
// to inform Windows that legacy x86 hardware (PIC, RTC, SMI) is absent.
//
// Body length for revision 6 = 244 bytes. We zero the entire body and set only
// the fields that matter for ARM hardware-reduced platforms:
//   - Flags: HW_REDUCED_ACPI bit set
//   - ArmBootArchFlags: PSCI_COMPLIANT + PSCI_USE_HVC (AETHER intercepts HVC)
//   - FADT major/minor revision
// ─────────────────────────────────────────────────────────────────────────────

/// FADT total length = header + body = 36 + 244 = 280 bytes.
pub const FADT_TOTAL_LEN: usize = ACPI_HEADER_LEN + FADT_BODY_LEN;

/// Build the FADT (Fixed ACPI Description Table) for ARM hardware-reduced ACPI.
pub fn build_fadt(
    buf: &mut [u8],
    oem_id: &[u8; 6],
    oem_table_id: &[u8; 8],
    oem_revision: u32,
) -> Result<usize, AcpiError> {
    let total = FADT_TOTAL_LEN;
    if buf.len() < total {
        return Err(AcpiError::BufferTooSmall);
    }
    write_header(
        buf,
        sig::FADT,
        total as u32,
        revision::FADT,
        oem_id,
        oem_table_id,
        oem_revision,
    )?;
    // Zero the entire body — most fields are unused on hardware-reduced ARM.
    for b in buf[ACPI_HEADER_LEN..total].iter_mut() {
        *b = 0;
    }
    // FADT.Flags at body offset 76 (header offset 112).
    let flags = fadt_flag::HW_REDUCED_ACPI | fadt_flag::LOW_POWER_S0_IDLE;
    buf[112..116].copy_from_slice(&flags.to_le_bytes());
    // ArmBootArchFlags at body offset 129 (header offset 165) — 16-bit field.
    let arm_flags = arm_boot_arch::PSCI_COMPLIANT | arm_boot_arch::PSCI_USE_HVC;
    buf[165..167].copy_from_slice(&arm_flags.to_le_bytes());
    // FADT minor revision at body offset 131 (header offset 167).
    buf[167] = 5; // ACPI 6.5
    finalize_table(buf, total)?;
    Ok(total)
}

// ─────────────────────────────────────────────────────────────────────────────
// AcpiTableSet — top-level container describing the ACPI tables AETHER
// produces for the Windows partition.
//
// This is a configuration / planning structure: it holds the inputs required
// to generate the table set and computes the total memory footprint. Actual
// table generation is performed by the build_* functions above into a buffer
// supplied by the caller (typically the bump allocator allocates this region
// in Windows partition memory).
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum number of CPU cores AETHER supports per partition.
pub const MAX_GICC_ENTRIES: usize = 16;
/// Maximum number of GIC Redistributor ranges.
pub const MAX_GICR_ENTRIES: usize = 4;
/// Maximum number of GIC ITS instances.
pub const MAX_ITS_ENTRIES: usize = 2;
/// Tables in the XSDT: FADT, MADT, GTDT, IORT.
pub const XSDT_TABLE_COUNT: usize = 4;

/// Total size (in bytes) of the complete ACPI table set including RSDP, XSDT,
/// FADT, MADT (with worst-case entry counts), GTDT, and IORT.
pub const fn acpi_total_size(n_gicc: usize, n_gicr: usize, n_its: usize) -> usize {
    RSDP_V2_LEN
        + xsdt_size(XSDT_TABLE_COUNT)
        + FADT_TOTAL_LEN
        + madt_size(n_gicc, n_gicr, n_its, true)
        + GTDT_TOTAL_LEN
        + IORT_MIN_LEN
}

/// Description of the Windows partition's ACPI table requirements.
#[derive(Debug)]
pub struct AcpiTableSet {
    /// Guest these tables describe.
    pub guest: GuestId,
    /// Number of CPU cores → number of GICC entries.
    pub cpu_count: usize,
    /// GIC Distributor entry.
    pub gicd: GicdEntry,
    /// GIC Redistributor range (typically one for all cores).
    pub gicr: GicrEntry,
    /// GIC ITS for MSI support.
    pub its: GicItsEntry,
    /// ARM timer interrupt configuration.
    pub timer: ArmTimerConfig,
    /// SMMUv3 node configuration.
    pub smmu: SmmuV3Node,
    /// Root Complex node configuration.
    pub root_complex: RootComplexNode,
}

impl AcpiTableSet {
    /// Compute total bytes required to lay out all tables in memory.
    pub fn total_size(&self) -> usize {
        acpi_total_size(self.cpu_count, 1, 1)
    }

    /// Validate that all entries are internally consistent.
    pub fn validate(&self) -> Result<(), AcpiError> {
        if self.cpu_count == 0 || self.cpu_count > MAX_GICC_ENTRIES {
            return Err(AcpiError::TooManyEntries);
        }
        if !matches!(
            self.gicd.gic_version,
            gic_version::V1 | gic_version::V2 | gic_version::V3 | gic_version::V4
        ) {
            return Err(AcpiError::InvalidGicVersion);
        }
        self.timer.validate()?;
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const OEM_ID: &[u8; 6] = b"AETHER";
    const OEM_TBL: &[u8; 8] = b"AETHWIN ";

    // ── Checksum primitives ───────────────────────────────────────────────────

    #[test]
    fn test_compute_checksum_zero_for_zero_input() {
        // Empty input → checksum = 0.
        assert_eq!(compute_checksum(&[]), 0);
    }

    #[test]
    fn test_compute_checksum_makes_sum_zero() {
        // For [1, 2, 3, 0], checksum byte should be 0x100 - 6 = 0xFA.
        let bytes = [1u8, 2, 3];
        let chk = compute_checksum(&bytes);
        let total: u8 = bytes.iter().fold(0u8, |a, &b| a.wrapping_add(b)).wrapping_add(chk);
        assert_eq!(total, 0);
    }

    #[test]
    fn test_verify_checksum_pass() {
        let bytes = [0x10u8, 0xF0]; // sum = 0
        assert_eq!(verify_checksum(&bytes), Ok(()));
    }

    #[test]
    fn test_verify_checksum_fail() {
        let bytes = [0x10u8, 0xF1]; // sum != 0
        assert_eq!(verify_checksum(&bytes), Err(AcpiError::ChecksumInvalid));
    }

    // ── Common header ─────────────────────────────────────────────────────────

    #[test]
    fn test_write_header_basic_fields() {
        let mut buf = [0u8; ACPI_HEADER_LEN];
        write_header(&mut buf, sig::MADT, ACPI_HEADER_LEN as u32, 5, OEM_ID, OEM_TBL, 0x42)
            .unwrap();
        assert_eq!(&buf[0..4], sig::MADT);
        assert_eq!(u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]), 36);
        assert_eq!(buf[8], 5);
        assert_eq!(buf[9], 0); // checksum still placeholder
        assert_eq!(&buf[10..16], OEM_ID);
        assert_eq!(&buf[28..32], b"AETH"); // Creator ID
    }

    #[test]
    fn test_finalize_table_sets_checksum() {
        let mut buf = [0u8; ACPI_HEADER_LEN];
        write_header(&mut buf, sig::MADT, ACPI_HEADER_LEN as u32, 5, OEM_ID, OEM_TBL, 0).unwrap();
        finalize_table(&mut buf, ACPI_HEADER_LEN).unwrap();
        // After finalize, checksum is correct.
        verify_checksum(&buf).unwrap();
    }

    #[test]
    fn test_finalize_length_mismatch() {
        let mut buf = [0u8; ACPI_HEADER_LEN];
        write_header(&mut buf, sig::MADT, 99, 5, OEM_ID, OEM_TBL, 0).unwrap();
        assert_eq!(
            finalize_table(&mut buf, ACPI_HEADER_LEN),
            Err(AcpiError::LengthMismatch)
        );
    }

    // ── RSDP ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_rsdp_signature_and_length() {
        let mut buf = [0u8; RSDP_V2_LEN];
        build_rsdp(&mut buf, OEM_ID, 0x4000_0000).unwrap();
        assert_eq!(&buf[0..8], RSDP_SIGNATURE);
        assert_eq!(buf[15], 2); // Revision
        assert_eq!(
            u32::from_le_bytes([buf[20], buf[21], buf[22], buf[23]]),
            RSDP_V2_LEN as u32
        );
    }

    #[test]
    fn test_rsdp_xsdt_address_round_trip() {
        let mut buf = [0u8; RSDP_V2_LEN];
        let xsdt_pa = 0x1234_5678_9ABC_DEF0u64;
        build_rsdp(&mut buf, OEM_ID, xsdt_pa).unwrap();
        let read = u64::from_le_bytes([
            buf[24], buf[25], buf[26], buf[27], buf[28], buf[29], buf[30], buf[31],
        ]);
        assert_eq!(read, xsdt_pa);
    }

    #[test]
    fn test_rsdp_both_checksums_valid() {
        let mut buf = [0u8; RSDP_V2_LEN];
        build_rsdp(&mut buf, OEM_ID, 0x4000_0000).unwrap();
        verify_rsdp(&buf).unwrap();
    }

    #[test]
    fn test_rsdp_corrupted_extended_checksum_detected() {
        let mut buf = [0u8; RSDP_V2_LEN];
        build_rsdp(&mut buf, OEM_ID, 0x4000_0000).unwrap();
        buf[33] ^= 0xFF; // corrupt a reserved byte (only affects v2 checksum)
        assert_eq!(verify_rsdp(&buf), Err(AcpiError::ChecksumInvalid));
    }

    #[test]
    fn test_rsdp_buffer_too_small() {
        let mut buf = [0u8; 30];
        assert_eq!(
            build_rsdp(&mut buf, OEM_ID, 0),
            Err(AcpiError::BufferTooSmall)
        );
    }

    // ── XSDT ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_xsdt_size_matches_formula() {
        assert_eq!(xsdt_size(0), 36);
        assert_eq!(xsdt_size(4), 36 + 32);
    }

    #[test]
    fn test_xsdt_build_and_verify() {
        let mut buf = [0u8; xsdt_size(4)];
        let addrs = [0x1000u64, 0x2000, 0x3000, 0x4000];
        let n = build_xsdt(&mut buf, OEM_ID, OEM_TBL, 1, &addrs).unwrap();
        assert_eq!(n, xsdt_size(4));
        verify_checksum(&buf).unwrap();
    }

    #[test]
    fn test_xsdt_null_address_rejected() {
        let mut buf = [0u8; xsdt_size(2)];
        let addrs = [0x1000u64, 0]; // second is NULL
        assert_eq!(
            build_xsdt(&mut buf, OEM_ID, OEM_TBL, 1, &addrs),
            Err(AcpiError::NullTableAddress)
        );
    }

    #[test]
    fn test_xsdt_addresses_round_trip() {
        let mut buf = [0u8; xsdt_size(2)];
        let addrs = [0xAAAA_BBBB_CCCC_DDDDu64, 0x1111_2222_3333_4444];
        build_xsdt(&mut buf, OEM_ID, OEM_TBL, 1, &addrs).unwrap();
        let read1 = u64::from_le_bytes([
            buf[36], buf[37], buf[38], buf[39], buf[40], buf[41], buf[42], buf[43],
        ]);
        assert_eq!(read1, addrs[0]);
    }

    // ── MADT entries ──────────────────────────────────────────────────────────

    fn make_gicc(uid: u32, mpidr: u64) -> GiccEntry {
        GiccEntry {
            cpu_interface_number: uid,
            acpi_processor_uid: uid,
            flags: 1, // enabled
            performance_interrupt: 23,
            parked_address: 0,
            gicr_base_address: 0x10_0000 + (uid as u64) * 0x20000,
            mpidr,
            vgic_maintenance_interrupt: 25,
        }
    }

    #[test]
    fn test_gicc_entry_size_and_type() {
        let mut buf = [0u8; MADT_GICC_ENTRY_LEN];
        let n = make_gicc(0, 0).write(&mut buf).unwrap();
        assert_eq!(n, 80);
        assert_eq!(buf[0], madt_entry::GICC);
        assert_eq!(buf[1], 80);
    }

    #[test]
    fn test_gicc_mpidr_field_at_offset_68() {
        let mut buf = [0u8; MADT_GICC_ENTRY_LEN];
        let mpidr = 0x0000_0001_0203_0405u64;
        make_gicc(0, mpidr).write(&mut buf).unwrap();
        let read = u64::from_le_bytes([
            buf[68], buf[69], buf[70], buf[71], buf[72], buf[73], buf[74], buf[75],
        ]);
        assert_eq!(read, mpidr);
    }

    #[test]
    fn test_gicd_entry_gic_v3() {
        let mut buf = [0u8; MADT_GICD_ENTRY_LEN];
        let entry = GicdEntry {
            gic_id: 0,
            physical_base_address: 0x1700_0000,
            gic_version: gic_version::V3,
        };
        let n = entry.write(&mut buf).unwrap();
        assert_eq!(n, 24);
        assert_eq!(buf[0], madt_entry::GICD);
        assert_eq!(buf[1], 24);
        assert_eq!(buf[20], 3);
    }

    #[test]
    fn test_gicd_entry_invalid_version_rejected() {
        let mut buf = [0u8; MADT_GICD_ENTRY_LEN];
        let entry = GicdEntry {
            gic_id: 0,
            physical_base_address: 0x1700_0000,
            gic_version: 9, // bogus
        };
        assert_eq!(entry.write(&mut buf), Err(AcpiError::InvalidGicVersion));
    }

    #[test]
    fn test_gicr_entry_size_and_type() {
        let mut buf = [0u8; MADT_GICR_ENTRY_LEN];
        let entry = GicrEntry {
            discovery_range_base_address: 0x17A0_0000,
            discovery_range_length: 0x10_0000,
        };
        let n = entry.write(&mut buf).unwrap();
        assert_eq!(n, 16);
        assert_eq!(buf[0], madt_entry::GICR);
        assert_eq!(buf[1], 16);
    }

    #[test]
    fn test_gic_its_entry_size_and_type() {
        let mut buf = [0u8; MADT_GIC_ITS_ENTRY_LEN];
        let entry = GicItsEntry {
            its_id: 0,
            physical_base_address: 0x1740_0000,
        };
        let n = entry.write(&mut buf).unwrap();
        assert_eq!(n, 20);
        assert_eq!(buf[0], madt_entry::GIC_ITS);
        assert_eq!(buf[1], 20);
    }

    // ── MADT full table ───────────────────────────────────────────────────────

    fn standard_gicd() -> GicdEntry {
        GicdEntry {
            gic_id: 0,
            physical_base_address: 0x1700_0000,
            gic_version: gic_version::V3,
        }
    }
    fn standard_gicr() -> GicrEntry {
        GicrEntry {
            discovery_range_base_address: 0x17A0_0000,
            discovery_range_length: 0x10_0000,
        }
    }
    fn standard_its() -> GicItsEntry {
        GicItsEntry {
            its_id: 0,
            physical_base_address: 0x1740_0000,
        }
    }

    #[test]
    fn test_madt_size_formula() {
        // 4 GICC + 1 GICD + 1 GICR + 1 ITS:
        // 36 + 8 + 4*80 + 24 + 16 + 20 = 424
        assert_eq!(madt_size(4, 1, 1, true), 424);
    }

    #[test]
    fn test_madt_build_4_cores_valid() {
        const SIZE: usize = madt_size(4, 1, 1, true);
        let mut buf = [0u8; SIZE];
        let gicc: [GiccEntry; 4] = [
            make_gicc(0, 0x0000),
            make_gicc(1, 0x0001),
            make_gicc(2, 0x0100),
            make_gicc(3, 0x0101),
        ];
        let n = build_madt(
            &mut buf,
            OEM_ID,
            OEM_TBL,
            1,
            &gicc,
            &standard_gicd(),
            &[standard_gicr()],
            &[standard_its()],
        )
        .unwrap();
        assert_eq!(n, SIZE);
        verify_checksum(&buf).unwrap();
        // Header signature.
        assert_eq!(&buf[0..4], sig::MADT);
        // First GICC entry begins at offset 36 + 8 = 44.
        assert_eq!(buf[44], madt_entry::GICC);
    }

    // ── GTDT ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_arm_timer_default_validates() {
        ArmTimerConfig::DEFAULT.validate().unwrap();
    }

    #[test]
    fn test_arm_timer_out_of_ppi_range_rejected() {
        let bad = ArmTimerConfig {
            virtual_el1_gsiv: 100, // SPI range, not PPI
            ..ArmTimerConfig::DEFAULT
        };
        assert_eq!(bad.validate(), Err(AcpiError::InvalidTimerInterrupt));
    }

    #[test]
    fn test_gtdt_total_length() {
        assert_eq!(GTDT_TOTAL_LEN, 96);
    }

    #[test]
    fn test_gtdt_build_valid_checksum() {
        let mut buf = [0u8; GTDT_TOTAL_LEN];
        let n = build_gtdt(&mut buf, OEM_ID, OEM_TBL, 1, &ArmTimerConfig::DEFAULT).unwrap();
        assert_eq!(n, GTDT_TOTAL_LEN);
        verify_checksum(&buf).unwrap();
        assert_eq!(&buf[0..4], sig::GTDT);
    }

    #[test]
    fn test_gtdt_timer_gsivs_round_trip() {
        let mut buf = [0u8; GTDT_TOTAL_LEN];
        build_gtdt(&mut buf, OEM_ID, OEM_TBL, 1, &ArmTimerConfig::DEFAULT).unwrap();
        // SecureEL1TimerGSIV at offset 48.
        let secure = u32::from_le_bytes([buf[48], buf[49], buf[50], buf[51]]);
        let nonsec = u32::from_le_bytes([buf[56], buf[57], buf[58], buf[59]]);
        let virt = u32::from_le_bytes([buf[64], buf[65], buf[66], buf[67]]);
        let el2 = u32::from_le_bytes([buf[72], buf[73], buf[74], buf[75]]);
        assert_eq!(secure, 29);
        assert_eq!(nonsec, 30);
        assert_eq!(virt, 27);
        assert_eq!(el2, 26);
    }

    // ── IORT ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_iort_min_length_constant() {
        assert_eq!(IORT_MIN_LEN, 184);
    }

    #[test]
    fn test_iort_build_valid_checksum() {
        let mut buf = [0u8; IORT_MIN_LEN];
        let smmu = SmmuV3Node {
            base_address: 0x1500_0000,
            event_interrupt: 74,
        };
        let rc = RootComplexNode {
            pcie_segment: 0,
            cache_coherent: true,
        };
        let n = build_iort(&mut buf, OEM_ID, OEM_TBL, 1, &smmu, &rc).unwrap();
        assert_eq!(n, IORT_MIN_LEN);
        verify_checksum(&buf).unwrap();
        assert_eq!(&buf[0..4], sig::IORT);
        // NumNodes == 2 at offset 36.
        assert_eq!(u32::from_le_bytes([buf[36], buf[37], buf[38], buf[39]]), 2);
        // First node type at offset 48 should be SMMU_V3.
        assert_eq!(buf[48], iort_node::SMMU_V3);
        // Second node type at offset 132 should be ROOT_COMPLEX.
        assert_eq!(buf[132], iort_node::ROOT_COMPLEX);
    }

    // ── FADT ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_fadt_total_length() {
        assert_eq!(FADT_TOTAL_LEN, 280);
    }

    #[test]
    fn test_fadt_build_valid_checksum() {
        let mut buf = [0u8; FADT_TOTAL_LEN];
        let n = build_fadt(&mut buf, OEM_ID, OEM_TBL, 1).unwrap();
        assert_eq!(n, FADT_TOTAL_LEN);
        verify_checksum(&buf).unwrap();
        assert_eq!(&buf[0..4], sig::FADT);
    }

    #[test]
    fn test_fadt_hardware_reduced_flag_set() {
        let mut buf = [0u8; FADT_TOTAL_LEN];
        build_fadt(&mut buf, OEM_ID, OEM_TBL, 1).unwrap();
        let flags = u32::from_le_bytes([buf[112], buf[113], buf[114], buf[115]]);
        assert!(flags & fadt_flag::HW_REDUCED_ACPI != 0);
    }

    #[test]
    fn test_fadt_arm_psci_hvc_flags_set() {
        let mut buf = [0u8; FADT_TOTAL_LEN];
        build_fadt(&mut buf, OEM_ID, OEM_TBL, 1).unwrap();
        let arm_flags = u16::from_le_bytes([buf[165], buf[166]]);
        assert!(arm_flags & arm_boot_arch::PSCI_COMPLIANT != 0);
        assert!(arm_flags & arm_boot_arch::PSCI_USE_HVC != 0);
    }

    // ── AcpiTableSet ─────────────────────────────────────────────────────────

    fn standard_table_set() -> AcpiTableSet {
        AcpiTableSet {
            guest: GuestId::Windows,
            cpu_count: 4,
            gicd: standard_gicd(),
            gicr: standard_gicr(),
            its: standard_its(),
            timer: ArmTimerConfig::DEFAULT,
            smmu: SmmuV3Node {
                base_address: 0x1500_0000,
                event_interrupt: 74,
            },
            root_complex: RootComplexNode {
                pcie_segment: 0,
                cache_coherent: true,
            },
        }
    }

    #[test]
    fn test_table_set_validate_passes() {
        standard_table_set().validate().unwrap();
    }

    #[test]
    fn test_table_set_zero_cores_fails() {
        let ts = AcpiTableSet {
            cpu_count: 0,
            ..standard_table_set()
        };
        assert_eq!(ts.validate(), Err(AcpiError::TooManyEntries));
    }

    #[test]
    fn test_table_set_too_many_cores_fails() {
        let ts = AcpiTableSet {
            cpu_count: 17,
            ..standard_table_set()
        };
        assert_eq!(ts.validate(), Err(AcpiError::TooManyEntries));
    }

    #[test]
    fn test_table_set_size_4_cores() {
        // RSDP(36) + XSDT(36+32=68) + FADT(280) + MADT(36+8+4*80+24+16+20=424)
        // + GTDT(96) + IORT(184) = 1088.
        assert_eq!(standard_table_set().total_size(), 1088);
    }

    // ── End-to-end: build full table set into adjacent buffers ───────────────

    #[test]
    fn test_end_to_end_table_set_all_checksums_valid() {
        let ts = standard_table_set();
        // Build each table into its own buffer; verify checksums independently.
        let mut rsdp_buf = [0u8; RSDP_V2_LEN];
        build_rsdp(&mut rsdp_buf, OEM_ID, 0x4000_1000).unwrap();
        verify_rsdp(&rsdp_buf).unwrap();

        let mut xsdt_buf = [0u8; xsdt_size(XSDT_TABLE_COUNT)];
        build_xsdt(
            &mut xsdt_buf,
            OEM_ID,
            OEM_TBL,
            1,
            &[0x4000_2000u64, 0x4000_3000, 0x4000_4000, 0x4000_5000],
        )
        .unwrap();
        verify_checksum(&xsdt_buf).unwrap();

        let mut fadt_buf = [0u8; FADT_TOTAL_LEN];
        build_fadt(&mut fadt_buf, OEM_ID, OEM_TBL, 1).unwrap();
        verify_checksum(&fadt_buf).unwrap();

        const MADT_SIZE: usize = madt_size(4, 1, 1, true);
        let mut madt_buf = [0u8; MADT_SIZE];
        let gicc: [GiccEntry; 4] = [
            make_gicc(0, 0),
            make_gicc(1, 1),
            make_gicc(2, 0x100),
            make_gicc(3, 0x101),
        ];
        build_madt(
            &mut madt_buf,
            OEM_ID,
            OEM_TBL,
            1,
            &gicc,
            &ts.gicd,
            &[ts.gicr],
            &[ts.its],
        )
        .unwrap();
        verify_checksum(&madt_buf).unwrap();

        let mut gtdt_buf = [0u8; GTDT_TOTAL_LEN];
        build_gtdt(&mut gtdt_buf, OEM_ID, OEM_TBL, 1, &ts.timer).unwrap();
        verify_checksum(&gtdt_buf).unwrap();

        let mut iort_buf = [0u8; IORT_MIN_LEN];
        build_iort(&mut iort_buf, OEM_ID, OEM_TBL, 1, &ts.smmu, &ts.root_complex).unwrap();
        verify_checksum(&iort_buf).unwrap();
    }

    // ── Constants / error variant coverage ───────────────────────────────────

    #[test]
    fn test_acpi_error_variants_distinct() {
        assert_ne!(AcpiError::BufferTooSmall, AcpiError::ChecksumInvalid);
        assert_ne!(AcpiError::SignatureInvalid, AcpiError::LengthMismatch);
        assert_ne!(AcpiError::InvalidGicVersion, AcpiError::InvalidTimerInterrupt);
    }

    #[test]
    fn test_signature_constants_are_4_chars() {
        assert_eq!(sig::XSDT.len(), 4);
        assert_eq!(sig::MADT.len(), 4);
        assert_eq!(sig::GTDT.len(), 4);
        assert_eq!(sig::IORT.len(), 4);
        assert_eq!(sig::FADT.len(), 4);
    }

    #[test]
    fn test_madt_entry_lengths_match_spec() {
        assert_eq!(MADT_GICC_ENTRY_LEN, 80);
        assert_eq!(MADT_GICD_ENTRY_LEN, 24);
        assert_eq!(MADT_GICR_ENTRY_LEN, 16);
        assert_eq!(MADT_GIC_ITS_ENTRY_LEN, 20);
    }
}
