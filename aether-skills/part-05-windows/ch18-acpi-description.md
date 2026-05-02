# SKILL.md — Chapter 18: The Windows ACPI Description

## Confidence Disclosure

**LOW for ARM-specific ACPI tables, MEDIUM for x86 ACPI (which is less relevant here).** ACPI on ARM is younger and less documented in general sources than ACPI on x86. The ARM-specific tables — GTDT, IORT, PPTT — are defined in ARM's SBBR specification rather than the core ACPI spec, and Claude's training on them is sparse. Mistakes in ACPI tables produce devices that Windows cannot find, cannot configure, or crashes trying to use.

## Required Primary Sources

**ACPI Specification** (latest, at uefi.org):

| Section | Topic | Priority |
|---|---|---|
| Chapter 5 | ACPI Software Programming Model | Read |
| Section 5.2 | ACPI System Description Tables | MANDATORY |
| Section 5.2.6 | RSDP | Critical |
| Section 5.2.7 | RSDT / XSDT | Critical |
| Section 5.2.12 | MADT | Critical for CPU/GIC description |
| Section 5.8 | FADT | Read |

**ARM Server Base Boot Requirements (SBBR) `DEN0044`** — Defines the ARM-specific ACPI tables that Windows-on-ARM depends on:

| Table | Purpose | Priority |
|---|---|---|
| GTDT | Generic Timer Description Table — ARM architectural timer | MANDATORY |
| IORT | I/O Remapping Table — describes SMMU topology | MANDATORY |
| PPTT | Processor Properties Topology Table — CPU cache hierarchy | Read |
| MADT | with ARM GIC entries | MANDATORY |

**Microsoft's documentation on Windows ARM64 ACPI requirements** — Available at docs.microsoft.com (search "Windows ARM ACPI requirements").

## Secondary Sources

**EDK2 ArmVirtPkg ACPI tables** at `ArmVirtPkg/AcpiTables/` — Reference ARM ACPI table implementations in EDK2. These are the most debugged open-source ARM ACPI tables available.

**Linux ACPI ARM64 parsing** at `drivers/acpi/arm64/` — Shows what Linux (and by extension the Android kernel) expects from ARM ACPI tables.

**Tianocore ACPI table validator** — EDK2 includes an ACPI table validation tool that checks table structure and checksums.

## Critical Concepts

**The Table Chain.** Windows discovers hardware through a specific chain: UEFI firmware provides a pointer to the RSDP (Root System Description Pointer) through the EFI Configuration Table. The RSDP points to the XSDT (Extended System Description Table). The XSDT is an array of 64-bit physical addresses, each pointing to a named ACPI table. AETHER constructs this entire chain from scratch for the Windows partition, including only hardware assigned to Windows.

**MADT For ARM.** The Multiple APIC Description Table (MADT) on x86 describes APIC interrupt controllers. On ARM, it describes the GIC. The ARM-specific MADT entries are:
- Type 0x0B: GIC CPU Interface — one per logical processor, describes the GIC CPU interface base address and flags
- Type 0x0C: GIC Distributor — one per system, describes GICD base address and GIC version
- Type 0x0E: GIC Redistributor — one per core or cluster depending on topology
- Type 0x0F: GIC Interrupt Translation Service — for MSI support

AETHER constructs a MADT that lists only the CPU cores assigned to Windows, with GIC addresses that AETHER has mapped into the Windows partition's address space.

**GTDT For ARM Timers.** The Generic Timer Description Table describes the ARM architectural timer to the OS. It specifies the secure and non-secure timer interrupt IDs, the timer base addresses (for memory-mapped access if needed), and the platform timer entries. Windows uses the GTDT to configure its timer. If the GTDT specifies wrong interrupt IDs, Windows timer interrupts will not be delivered and the system will appear to freeze.

**IORT For SMMU.** The I/O Remapping Table describes the SMMU topology to the OS — which DMA masters are connected to which SMMU, and the stream ID mapping. Windows uses the IORT to configure its IOMMU driver. If the IORT is incorrect, Windows device drivers may not be able to perform DMA. The IORT is also used by Windows's Secure Boot and Virtualization Based Security (VBS) features, so an incorrect IORT can cause security-related boot failures.

**Table Checksums.** Every ACPI table has an 8-bit checksum field such that the sum of all bytes in the table (including the checksum byte) equals zero modulo 256. If the checksum is wrong, Windows refuses to use the table. AETHER's ACPI table builder must compute and set the checksum correctly after constructing each table.

**Dynamic Vs. Static Tables.** AETHER must generate ACPI tables dynamically at boot time because the contents depend on the partition configuration (which cores, which memory, which devices were assigned to Windows). The tables cannot be hardcoded. AETHER's table builder produces binary-formatted tables in memory, computes their checksums, links them into the XSDT, and places the RSDP where Windows's UEFI boot path expects to find it.

## Common AI Mistakes In This Domain

Claude generates ACPI tables for x86 (with APIC entries, LAPIC addresses, I/O APIC entries) rather than ARM (with GIC entries). x86 ACPI tables will cause Windows-on-ARM to fail device initialization.

Claude generates ACPI table size fields that don't match the actual table contents, producing checksum failures.

Claude omits the GTDT entirely, which causes Windows to fail timer initialization.

Claude generates MADT entries with wrong GIC version numbers. GICv2 MADT entries differ from GICv3 entries and using the wrong version causes the GIC driver to malfunction.

Claude generates IORT with wrong stream ID mappings that don't match the SMMU configuration, causing DMA failures for passed-through devices.

## Verification Protocol

For every synthesized ACPI table:
1. Verify the Signature field matches the table name (4 ASCII characters)
2. Verify the Length field equals the actual byte count of the table
3. Compute the checksum: sum all bytes, verify the result is 0x00 mod 256
4. Verify the Revision field matches the version in the relevant spec
5. Validate against EDK2's ACPI validator tool before booting Windows

For the MADT:
1. Verify GIC CPU Interface entries have correct ACPI Processor UID matching the DSDT
2. Verify GIC Distributor entry has correct GICD base address as mapped in Windows's address space
3. Verify GIC version field matches the actual GIC hardware version

For the GTDT:
1. Verify timer interrupt IDs match the actual interrupt IDs in the GIC configuration
2. Verify timer base addresses (if memory-mapped) are correct

## Pre-Flight Checklist

- [ ] Download ACPI spec and read Section 5.2 completely
- [ ] Download SBBR `DEN0044` and read the ACPI requirements chapter
- [ ] Study EDK2's `ArmVirtPkg/AcpiTables/` — these are tested, working ARM ACPI tables
- [ ] Install an ACPI table viewer (e.g., `acpidump` + `acpixtract` + `iasl` on Linux) and dump the real ACPI tables from an ARM laptop — study them before writing your own
- [ ] Write an ACPI table validator function that checks signature, length, and checksum before AETHER uses any synthesized table
- [ ] Test synthesized ACPI tables by booting QEMU with them and checking that the Linux kernel (a strict ACPI consumer) accepts them before testing with Windows
