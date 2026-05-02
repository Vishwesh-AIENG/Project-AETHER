# Claude's Confidence Matrix For AETHER

This document is a candid map of where Claude's knowledge is reliable and where it is not, across every technical surface AETHER touches. Use it to calibrate trust in AI-generated output.

The grading is:
- **HIGH** — Claude has consistent, well-trained knowledge. Output is usually correct, but still verify against primary sources.
- **MEDIUM** — Claude has working conceptual understanding but specific details (bit fields, register layouts, exact opcodes, version-specific behavior) require verification.
- **LOW** — Claude has fragmentary or potentially outdated knowledge. Always cross-reference against primary sources before trusting any specific claim.
- **NONE** — Claude has minimal exposure. Treat output as a starting point for research, not as authoritative.

## ARM64 Architecture

| Topic | Confidence | Notes |
|---|---|---|
| ARM64 instruction set fundamentals | MEDIUM | Conceptual understanding solid; exact instruction encodings need verification |
| Exception levels EL0–EL3 | MEDIUM | Behavior in normal cases known; edge cases in transitions less reliable |
| MMU concepts (Stage 1) | MEDIUM | General OS textbook level; ARM64 specifics need ARM ARM |
| Stage 2 translation | LOW | Concept understood; descriptor format and attribute encoding need primary source |
| TLB maintenance instructions | LOW | Inner-shareable vs outer-shareable distinctions easy to get wrong |
| GIC v2 architecture | MEDIUM | Older, more documented |
| GIC v3/v4 architecture | LOW | Especially virtual interrupt injection (LRs, ICH_LR registers) |
| SMMU v3 | LOW | Stream table format, context descriptors need primary source |
| Architectural timer | MEDIUM | Basic operation; cross-VM timer handling less reliable |
| ARMv9-A specifics | LOW | Newer than typical training cutoff |

## Hypervisor Engineering

| Topic | Confidence | Notes |
|---|---|---|
| Type-1 hypervisor architecture concepts | HIGH | Well-documented field |
| EL2 setup sequences | LOW | Specific register configuration needs primary source |
| KVM internals (reference) | MEDIUM | General architecture known; specific source files vary |
| Xen on ARM internals | LOW | Less common in training data |
| Memory ballooning, NUMA, etc. | MEDIUM | Mostly irrelevant to AETHER's static partitioning model |
| VM exit handling patterns | MEDIUM | Concepts solid; ARM-specific details need verification |

## Boot And Firmware

| Topic | Confidence | Notes |
|---|---|---|
| UEFI fundamentals | MEDIUM | x86 UEFI better-known than ARM UEFI |
| ARM Trusted Firmware (TF-A) | LOW | Specialized ecosystem |
| ACPI tables (general) | MEDIUM | Older spec well-known |
| ACPI for ARM (SBSA, MADT specifics) | LOW | Newer, less documented in training |
| Device Tree (DTB) format | MEDIUM | Linux convention well-known |
| Android Verified Boot (AVB) | LOW | Specific cryptographic chains need official spec |

## Linux And Android

| Topic | Confidence | Notes |
|---|---|---|
| Linux kernel general architecture | HIGH | Well-trained |
| Linux ARM64 kernel specifics | MEDIUM | Architecture-specific code less covered |
| Linux KVM source code | MEDIUM | Public, often referenced |
| Android Common Kernel patches | LOW | Diverges from upstream in specific ways |
| AOSP build system (Soong/Make) | MEDIUM | Concepts good; specific Android.bp syntax varies |
| Android HAL interfaces | MEDIUM | General structure known; specific HAL APIs vary by version |
| ART runtime internals | LOW | Implementation detail mostly opaque |
| Android device tree configuration | LOW | Vendor-specific conventions |
| microG architecture | LOW | Project-specific knowledge |

## Hardware-Specific

| Topic | Confidence | Notes |
|---|---|---|
| Snapdragon X Elite specifics | NONE | Mostly NDA-protected; rely on Qualcomm docs |
| Adreno GPU command format | NONE | Proprietary |
| Adreno open-source driver (Freedreno/Turnip) | LOW | Reverse-engineered, evolving |
| NVMe SSD specification | MEDIUM | Public NVMe spec well-documented |
| NVMe namespaces and SR-IOV | LOW | Newer features, less coverage |
| xHCI USB controller spec | LOW | Detailed register-level work needs the spec |
| PCIe SR-IOV | MEDIUM | Generally documented; vendor extensions vary |

## Windows-on-ARM

| Topic | Confidence | Notes |
|---|---|---|
| Windows boot sequence | MEDIUM | NT loader well-documented |
| Windows-on-ARM specifics | LOW | Less documented than x86 Windows |
| WHQL driver requirements | LOW | Microsoft-specific compliance |
| HyperV TLFS (for reference) | LOW | Useful as a comparison point |

## Build And Tooling

| Topic | Confidence | Notes |
|---|---|---|
| Rust language and Cargo | HIGH | Well-trained |
| Rust on bare metal / no_std | MEDIUM | Less common patterns |
| ARM64 cross-compilation | MEDIUM | General toolchain knowledge |
| QEMU ARM64 system emulation | MEDIUM | Often used for development |
| AOSP repo / build orchestration | MEDIUM | Documented but complex |

## What This Matrix Means In Practice

Anywhere the matrix shows LOW or NONE, AI-generated code should be treated as a draft that needs verification against primary sources by a human who has read those sources. The Pre-Flight Checklist in each chapter's SKILL.md tells you which sources to read first.

Anywhere the matrix shows HIGH, AI-generated code is more likely to be correct on first attempt, but should still be tested rigorously because correctness in systems software is binary.

This matrix should be revisited and updated as the project progresses and as you discover specific failure modes in practice. The goal is honest calibration, not flattery.
