# SKILL.md — Chapter 17: Windows As A Guest

## Confidence Disclosure

**LOW for Windows-on-ARM internals, MEDIUM for general Windows boot concepts.** Windows-on-ARM is less documented in public sources than x86 Windows. Microsoft's internal documentation is not public. The interaction between Windows-on-ARM and ARM hypervisors is an area where Claude's training is sparse and potentially outdated.

## Required Primary Sources

**Microsoft Hypervisor Top-Level Functional Specification (TLFS)** — Available at github.com/MicrosoftDocs/Virtualization-Documentation. While AETHER is not implementing Hyper-V, the TLFS documents what Windows expects from a hypervisor environment, which AETHER must provide or emulate.

| Section | Topic | Priority |
|---|---|---|
| Chapter 2 | Architectural overview | Read |
| Chapter 3 | Virtual processor | Read |
| Chapter 4 | Memory | Read for CPUID implications |
| Chapter 12 | Enlightenments | Read — Windows uses these for performance |

**UEFI Specification** — Windows-on-ARM boots via UEFI. Same reference as Chapter 7.

**ACPI Specification** — Windows uses ACPI for hardware discovery. Same reference as Chapter 7.

**Windows ARM64 ABI** — Microsoft's documentation at docs.microsoft.com for the ARM64 calling convention and system register usage on Windows.

## Secondary Sources

**Windows Hardware Lab Kit (HLK)** documentation — Describes what hardware Windows requires, indirectly revealing what firmware must provide.

**Project Mu** at github.com/microsoft/mu — Microsoft's open-source UEFI firmware implementation for Windows devices. Reveals what UEFI services Windows depends on.

**EDK2 ArmVirtPkg** at `ArmVirtPkg/` in edk2 — UEFI platform for ARM virtual machines. Shows how a minimal ARM UEFI environment is constructed.

## Critical Concepts

**CPUID And Hypervisor Identity.** Windows's kernel probes for a hypervisor using the CPUID instruction. Specifically, CPUID with EAX=0x40000000 returns the hypervisor vendor string (in EBX, ECX, EDX), and EAX=0x40000001 returns the hypervisor interface identifier. If AETHER does not intercept these CPUID calls and return appropriate values, Windows may detect an unrecognized hypervisor and behave unpredictably. AETHER should return either a neutral vendor string or implement a minimal subset of Hyper-V enlightenments that Windows recognizes. The ARM ARM defines CPUID emulation requirements for EL2.

**Hyper-V Enlightenments.** Windows is optimized to run under Hyper-V and uses "enlightenments" — paravirtualized optimizations that bypass slower emulated hardware paths when running in a Hyper-V environment. The most important are the synthetic timer (replacing APIC timer), the hypercall interface (for TLB flushes), and the MSR-based interrupt control (replacing LAPIC MMIO). If AETHER advertises Hyper-V compatibility via CPUID, Windows will use these enlightenments and AETHER must implement them. If AETHER does not advertise Hyper-V compatibility, Windows falls back to standard (slower) hardware interfaces. The choice involves a trade-off between implementation complexity (implementing enlightenments) and performance (enlightened Windows is significantly faster under a hypervisor).

**Secure Boot.** Windows-on-ARM requires Secure Boot by default. The UEFI firmware presented to Windows must maintain a valid Secure Boot chain from the UEFI Secure Boot keys through the Windows Boot Manager signature. AETHER's Windows partition firmware must include the correct Microsoft Windows Production CA key in its Secure Boot database (db), the forbidden signatures list (dbx), and the Platform Key (PK) and Key Exchange Key (KEK) as Microsoft expects them. If Secure Boot fails, Windows will not boot.

**Driver Signing.** All Windows drivers must be Microsoft-signed. AETHER does not need to provide custom Windows drivers — Windows uses its own ARM64 drivers for standard hardware (standard ARM GIC, ARM UART, standard PCIe, etc.). The hardware AETHER presents to Windows must be hardware that Windows already has inbox drivers for. Custom hardware that requires a third-party driver would require driver signing infrastructure that is impractical for a hypervisor project to establish.

**Windows Crash Dump.** When Windows crashes, it writes a crash dump to the paging file on its storage device. AETHER must ensure Windows's assigned NVMe namespace has sufficient space for crash dumps (typically equal to the amount of RAM assigned to Windows). If the crash dump cannot be written, Windows will reboot immediately on crash without preserving diagnostic information.

## Common AI Mistakes In This Domain

Claude generates CPUID emulation code that returns incorrect EAX=0x40000000 values, causing Windows to either not detect a hypervisor (and use slower hardware paths) or detect an incompatible hypervisor.

Claude suggests implementing custom Windows drivers for AETHER-specific features. Custom drivers require WHQL signing, which is impractical. AETHER must work with inbox Windows drivers only.

Claude omits Secure Boot configuration, producing a firmware environment where Windows refuses to boot.

Claude suggests modifying Windows or injecting code into the Windows partition for AETHER integration. AETHER must work with a completely unmodified Windows installation.

## Verification Protocol

For the Windows boot environment:
1. Test the synthesized ACPI tables against real Windows-on-ARM by booting in QEMU with OVMF before testing on AETHER hardware
2. Verify Secure Boot chain by checking that Windows reports Secure Boot as enabled after first boot
3. Verify that no custom drivers are installed — Device Manager should show all devices using inbox Microsoft drivers

For CPUID emulation:
1. Use a tool like CPU-Z inside Windows to verify the hypervisor vendor string AETHER reports
2. Verify Windows's performance is acceptable — if it is 10× slower than expected, enlightenments may be needed

## Pre-Flight Checklist

- [ ] Download Microsoft Hypervisor TLFS from GitHub and read Chapters 2–4
- [ ] Study Project Mu for UEFI firmware patterns Microsoft expects
- [ ] Install Windows-on-ARM in QEMU using OVMF as a baseline — verify it boots without AETHER before adding AETHER's environment
- [ ] Read Microsoft's documentation on Secure Boot key hierarchy
- [ ] Determine whether AETHER will implement Hyper-V enlightenments — document this decision before writing any CPUID emulation code
