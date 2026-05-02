# AETHER Primary Sources Library

This is the master bibliography of authoritative documents referenced across all AETHER skills. Every document listed here is freely available unless otherwise noted. Acquire all of them and keep them in a `references/` directory adjacent to your source tree.

## ARM Architecture (Tier 1 — Most Critical)

**ARM Architecture Reference Manual for Armv8-A and Armv9-A** (`DDI0487`)
- The single most important document for AETHER. Approximately 12,000 pages.
- Source: developer.arm.com (free download, registration required)
- Cited internally as "ARM ARM" throughout these skills

**ARM System Memory Management Unit Architecture Specification, Version 3** (`IHI0070`)
- Defines the SMMU v3 used for DMA isolation
- Source: developer.arm.com

**ARM Generic Interrupt Controller Architecture Specification, Version 3 and 4** (`IHI0069`)
- Defines GICv3/v4 including the Virtualization Extensions
- Source: developer.arm.com

**ARM Server Base System Architecture (SBSA)** (`DEN0029`)
- Defines the standard ARM server platform AETHER targets
- Source: developer.arm.com

**ARM Server Base Boot Requirements (SBBR)** (`DEN0044`)
- Boot architecture requirements for ARM servers/laptops
- Source: developer.arm.com

## Firmware And Boot

**UEFI Specification** (latest version)
- Source: uefi.org
- Particularly the ARM-specific binding sections

**ACPI Specification** (latest version)
- Source: uefi.org
- Particularly the ARM-specific tables: MADT, GTDT, IORT, PPTT

**ARM Trusted Firmware (TF-A) documentation**
- Source: trustedfirmware.org
- Open source reference EL3 firmware

## Storage And Peripherals

**NVM Express Base Specification** (latest version)
- Source: nvmexpress.org
- Particularly Chapter 8 (Namespaces) and the SR-IOV sections

**xHCI Specification (eXtensible Host Controller Interface for USB)**
- Source: intel.com
- For USB controller passthrough work

**PCI Express Base Specification** (latest version)
- Source: pcisig.com (membership required for newer revisions; older revisions partially public)

**SR-IOV Specification** (PCI-SIG)
- Source: pcisig.com

## Linux Kernel

**Linux source tree** at `kernel.org`
- Particularly `arch/arm64/kvm/` for KVM ARM reference
- `Documentation/arm64/` for architecture-specific docs
- `drivers/iommu/arm/` for SMMU drivers

**Android Common Kernel** at `android.googlesource.com/kernel/common`
- Google's curated kernel branch

## Android

**Android Open Source Project (AOSP)** at `source.android.com`
- Documentation site and source tree
- Particularly the "Devices" section for HAL specifications

**Android Compatibility Definition Document (CDD)**
- Source: source.android.com
- Defines what makes a device Android-compatible

**Android Verified Boot 2.0 specification**
- Source: android.googlesource.com/platform/external/avb

**microG project**
- Source: github.com/microg
- Documentation in the project READMEs

## Reference Hypervisor Implementations

**Linux KVM source** — `arch/arm64/kvm/` in the kernel tree

**Xen on ARM** — `xen/arch/arm/` in xen-project source

**Hypervisor Framework documentation (Apple)** — for architectural ideas only, not directly applicable

## Vendor Documentation (NDA Or Limited)

**Qualcomm Snapdragon X Elite Technical Reference Manual**
- Requires NDA with Qualcomm
- Essential for platform-specific work
- Public partial information available in datasheets

**Adreno GPU documentation**
- Mostly proprietary; some information available through Freedreno/Mesa open-source drivers
- `freedreno.org` and Mesa source code

## Standards And Specifications (Reference)

**Open Container Initiative (OCI) specifications** — for container concepts that inform paravirtualized device design

**virtio specifications** — explicitly NOT used by AETHER (since virtio is paravirtualization), but valuable as a comparison point for what NOT to do

## Books And Background Reading

**"Operating Systems: Three Easy Pieces"** by Remzi and Andrea Arpaci-Dusseau
- Free online at pages.cs.wisc.edu/~remzi/OSTEP/
- Excellent foundation for memory management, scheduling, virtualization concepts

**"Computer Architecture: A Quantitative Approach"** by Hennessy and Patterson
- Standard reference for computer architecture fundamentals

**"Linux Kernel Development"** by Robert Love
- Solid Linux internals primer

**"Android Internals"** by Jonathan Levin
- Two-volume deep dive into Android architecture

## Acquisition Priority

If you can only acquire a subset of these to start:
1. ARM ARM (`DDI0487`) — non-negotiable
2. ARM SMMU v3 spec (`IHI0070`) — for memory isolation work
3. ARM GIC v3 spec (`IHI0069`) — for interrupt routing
4. Linux kernel source (free, just clone the git repo)
5. AOSP source (free, but enormous — 200+ GB after build)
6. ACPI specification — for firmware work

Everything else can be acquired as the project advances into the relevant chapters.
