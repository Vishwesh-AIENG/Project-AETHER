# SKILL.md — Chapter 7: Boot

## Confidence Disclosure

**LOW.** Claude understands UEFI boot concepts at a general level but has weak knowledge of ARM-specific UEFI, the EFI handoff protocol on ARM laptops specifically, and the interaction between UEFI, TF-A, and a custom EL2 payload. The boot sequence is a one-shot operation — if it fails, nothing else runs. Mistakes here produce silent hangs, not debuggable crashes.

## Required Primary Sources

**UEFI Specification** (latest, available at uefi.org):

| Section | Topic | Priority |
|---|---|---|
| Chapter 2 | Overview | Read first |
| Chapter 7 | Services — Boot Services | Essential |
| Chapter 8 | Services — Runtime Services | Read |
| Chapter 9 | Protocols | Reference as needed |
| Section 13.4 | Simple Text Output Protocol | Useful for early debug output |

**ARM Server Base Boot Requirements (SBBR) `DEN0044`** — Defines what ARM-compliant firmware must provide. AETHER's boot process depends on the firmware satisfying SBBR.

**ARM Trusted Firmware (TF-A) documentation** at trustedfirmware.org:

| Document | Topic | Priority |
|---|---|---|
| Firmware Design | Overall architecture | Read completely |
| Porting Guide | Platform-specific hooks | Essential for integration |
| EL3 to EL2 handoff | Transition to AETHER | Critical |

**ACPI Specification** (available at uefi.org) — Chapters 5 and 6 on hardware description tables.

## Secondary Sources

**EDK2 (EFI Development Kit)** at github.com/tianocore/edk2 — The reference UEFI implementation. AETHER may implement itself as a UEFI application using EDK2, or receive UEFI boot services and exit them. Either way EDK2 source is the authoritative reference for how UEFI applications interact with firmware.

**edk2-platforms** at github.com/tianocore/edk2-platforms — ARM platform-specific UEFI code, showing how real ARM UEFI implementations look.

**Xen UEFI boot** at `xen/arch/arm/arm64/head.S` — Shows how Xen handles the transition from UEFI to a bare-metal hypervisor.

**Linux UEFI boot stub** at `arch/arm64/boot/efi-stub.S` — Shows how Linux receives control from UEFI on ARM64.

## Critical Concepts

**The Boot Sequence.** The physical sequence of control transfer on an ARM64 laptop is: ROM → Platform firmware (UEFI) → EL3 secure firmware (TF-A) → AETHER (EL2) → Guests (EL1). AETHER receives control after TF-A has initialized the secure world and dropped to EL2 via an ERET. AETHER must not return from this ERET — it must set up its own environment and never return to TF-A during normal operation.

**UEFI Application vs UEFI Loader vs UEFI OS Loader.** AETHER presents itself to the firmware as a UEFI OS Loader (EFI_IMAGE_SUBSYSTEM_EFI_APPLICATION or the OS loader image type). The firmware loads it into memory, provides it with the EFI System Table pointer (which is how AETHER accesses firmware services), and transfers execution to AETHER's entry point. AETHER uses UEFI boot services to discover hardware (ACPI tables, memory map), then calls ExitBootServices() to take exclusive ownership of the hardware.

**ExitBootServices().** This is the most critical call in the boot sequence. After ExitBootServices(), the firmware boot services are gone, the firmware's interrupt handlers are gone, and AETHER owns everything. The call returns a final memory map that is the authoritative description of physical memory. AETHER must parse this memory map immediately and save it before proceeding, because it describes which physical memory regions are usable (EfiConventionalMemory), which are firmware runtime regions (EfiRuntimeServicesData), and which are reserved (EfiReservedMemoryType). Getting the memory map wrong corrupts either Windows's or Android's memory regions.

**ACPI Table Discovery.** AETHER uses UEFI's GetSystemTable()->ConfigurationTable to find the RSDP (Root System Description Pointer), which leads to the XSDT (Extended System Description Table), which lists all ACPI tables. From the XSDT, AETHER locates the MADT (Multiple APIC Description Table) for CPU topology, the GTDT (Generic Timer Description Table) for timer configuration, the IORT (I/O Remapping Table) for SMMU information, and the DSDT/SSDT for device descriptions. Claude knows the general ACPI table chain but gets ARM-specific table formats wrong.

**The Handoff To Guests.** After ExitBootServices() and after partitioning resources, AETHER starts each guest by constructing an EFI-compatible environment for that guest, loading the guest's first-stage bootloader into the guest's memory, configuring Stage 2 translation for that guest, and performing an ERET to EL1 in the guest's context. The guest's bootloader (e.g., the Windows Boot Manager or the Android bootloader) then runs at EL1 and proceeds normally.

## Common AI Mistakes In This Domain

Claude generates ExitBootServices() call sequences that don't retry on EFI_INVALID_PARAMETER — which is required because the memory map may have changed between the GetMemoryMap() call and the ExitBootServices() call.

Claude builds ACPI table parsing code that assumes tables are contiguous in memory. They are not. Each table has its own physical address and must be mapped before access.

Claude generates EL2 setup code that runs before the stage 2 page tables are established, which means any memory access that misses the cache could fetch from the wrong physical address.

Claude often conflates physical addresses and virtual addresses in boot code. In early boot before MMU setup, all addresses are physical. Claude sometimes generates code using virtual address constants that are only valid after MMU is on.

## Verification Protocol

For boot sequence code Claude produces:
1. Verify ExitBootServices() is called exactly once and that the code path handles EFI_INVALID_PARAMETER with a retry
2. Verify that after ExitBootServices() no EFI boot services are called (they are undefined after this point)
3. Verify ACPI table parsing against the ACPI spec — every table has a specific Length field and Signature, and both must be validated before trusting the table content
4. Verify that Stage 2 translation is established before any guest address space is accessed
5. Test the entire boot sequence in QEMU with OVMF (Open Virtual Machine Firmware) as the UEFI provider before testing on real hardware

## Pre-Flight Checklist

- [ ] Download and read UEFI Specification Chapters 7 and 8
- [ ] Download SBBR `DEN0044` and read completely
- [ ] Clone EDK2: `git clone https://github.com/tianocore/edk2.git`
- [ ] Build a simple UEFI application with EDK2 that prints "Hello from EL2" and reads the memory map — run it in QEMU with OVMF
- [ ] Read TF-A Firmware Design document at trustedfirmware.org
- [ ] Study Xen's UEFI boot path in `xen/arch/arm/`
- [ ] Understand what the EFI memory map types mean — draw the physical memory layout of a typical ARM laptop and label each region
