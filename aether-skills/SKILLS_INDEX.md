# AETHER Skills Index

This directory contains a SKILL.md file for every chapter of the AETHER architecture book. Each SKILL.md is a knowledge bibliography that an AI assistant must consult **before** writing or reviewing code in that chapter's domain.

The skills exist because Claude (and any LLM) has uneven knowledge across the technical surfaces AETHER touches. Some areas — high-level OS theory, build systems, the Rust language — Claude knows well from training. Others — specific ARM64 page table descriptor bit fields, GIC v3 virtual interrupt injection, Adreno GPU command formats — require primary source consultation because Claude's training data on them is sparse, incomplete, or partially incorrect.

Each SKILL.md follows a consistent structure:
1. **Confidence Disclosure** — honest assessment of where Claude's knowledge is solid and where it is weak
2. **Required Primary Sources** — authoritative documents that must be read before implementation, with specific section numbers
3. **Secondary Sources** — useful reference implementations and supplementary material
4. **Critical Concepts** — the small number of ideas that must be internalized before any code is written
5. **Common AI Mistakes** — specific failure modes Claude exhibits in this area
6. **Verification Protocol** — how to validate AI-generated code against authoritative sources
7. **Pre-Flight Checklist** — concrete tasks to complete before starting implementation

## How To Use These Skills

Before starting work on any chapter, paste the contents of that chapter's SKILL.md into your conversation with Claude. This serves the same purpose as the system-level skill files in Anthropic's tooling: it primes Claude with the specific knowledge boundaries and authoritative references for that domain, reducing the chance of confident-but-wrong output.

For implementation work, the workflow is:
1. Read the chapter in the README
2. Open the corresponding SKILL.md
3. Follow the Pre-Flight Checklist (read the listed primary sources yourself)
4. Then begin Claude collaboration sessions with the SKILL.md as context

For code review, paste the SKILL.md alongside the code being reviewed and ask Claude to check the code against the Verification Protocol.

## Index Of Skills

### Part I — The Vision (Low Technical Density)
- `part-01-vision/SKILL.md` — Chapters 1–3, design principles and constraints

### Part II — The Silicon
- `part-02-silicon/ch04-arm64-substrate.md` — ARM64 as the foundation
- `part-02-silicon/ch05-exception-levels.md` — EL0–EL3 hierarchy
- `part-02-silicon/ch06-virtualization-extensions.md` — VHE, Stage 2, GIC virt

### Part III — The Hypervisor
- `part-03-hypervisor/ch07-boot.md` — UEFI handoff and hypervisor initialization
- `part-03-hypervisor/ch08-memory-architecture.md` — Stage 2 translation and SMMU
- `part-03-hypervisor/ch09-cpu-partitioning.md` — Static core assignment
- `part-03-hypervisor/ch10-interrupt-routing.md` — GIC virtual interrupt routing

### Part IV — Device Strategy
- `part-04-devices/ch11-passthrough-principle.md` — Architectural philosophy
- `part-04-devices/ch12-paravirtualization.md` — Modem, sensors, phone-specific peripherals
- `part-04-devices/ch13-gpu-sriov.md` — SR-IOV graphics partitioning
- `part-04-devices/ch14-storage.md` — NVMe namespace partitioning
- `part-04-devices/ch15-network.md` — Network adapter strategies
- `part-04-devices/ch16-usb-input.md` — USB controller assignment

### Part V — The Windows Partition
- `part-05-windows/ch17-windows-as-guest.md` — Windows-on-ARM as a guest OS
- `part-05-windows/ch18-acpi-description.md` — Synthesized ACPI tables

### Part VI — The Android Partition
- `part-06-android/ch19-bootloader.md` — Android Verified Boot
- `part-06-android/ch20-linux-kernel.md` — Android Common Kernel
- `part-06-android/ch21-aosp-userspace.md` — Building AOSP for AETHER
- `part-06-android/ch22-microg.md` — Google Play Services substitution
- `part-06-android/ch23-play-store.md` — App distribution alternatives

### Part VII — Cross-Cutting Concerns
- `part-07-cross-cutting/ch24-performance.md` — Performance philosophy
- `part-07-cross-cutting/ch25-security.md` — Security model
- `part-07-cross-cutting/ch26-time.md` — Time and timer fidelity

### Part VIII — Build And Toolchain
- `part-08-build/ch27-build-system.md` — Multi-language build orchestration
- `part-08-build/ch28-development-workflow.md` — Cross-compilation and testing

### Part IX — Roadmap (Process, Not Technical)
- `part-09-roadmap/SKILL.md` — Chapters 29–33, phase planning

### Meta
- `_meta/HOW_TO_USE.md` — Detailed workflow guide
- `_meta/CLAUDE_CONFIDENCE_MATRIX.md` — Where Claude is strong vs weak across the project
- `_meta/PRIMARY_SOURCES_LIBRARY.md` — Master bibliography of all referenced documents
