# SKILL.md — Chapter 9: CPU Partitioning

## Confidence Disclosure

**MEDIUM.** The concept of static CPU partitioning is well understood and Claude explains it correctly at the architectural level. The implementation-level risks are in the details of MPIDR-based core identification, affinity-based routing tables in the GIC, and the specific sequence required to bring secondary cores online in a partitioned configuration. These details are hardware-specific enough to require primary source verification.

## Required Primary Sources

**ARM ARM `DDI0487`:**

| Section | Topic | Priority |
|---|---|---|
| Section D1.8 | Multiprocessing extensions | Read completely |
| Section D7.2.74 | MPIDR_EL1 register description | Critical |
| Section G5 | EL2 system registers | Reference |

**ARM GIC Architecture Specification v3 `IHI0069`:**

| Section | Topic | Priority |
|---|---|---|
| Section 2.2 | SPI routing | Read completely |
| Chapter 4 | Distributor | Read for affinity routing |
| Section 4.8 | GICD_IROUTER — SPI routing registers | Critical |

**PSCI (Power State Coordination Interface) Specification `DEN0022`** — available at developer.arm.com. Defines the CPU_ON, CPU_OFF, and related calls that AETHER intercepts when guests try to bring secondary cores online.

## Secondary Sources

**Linux kernel `arch/arm64/kernel/smp.c`** — Secondary CPU bring-up sequence in Linux. Shows what a guest kernel does when it tries to start a second core, which AETHER must intercept and control.

**KVM ARM CPU handling** at `arch/arm64/kvm/arm.c` and `arch/arm64/kvm/psci.c` — KVM's PSCI emulation, which is directly applicable to AETHER's guest CPU management.

**TF-A PSCI implementation** at `lib/psci/` — The reference implementation of PSCI from the secure firmware side.

## Critical Concepts

**MPIDR — Multiprocessor Affinity Register.** Each CPU core has an MPIDR_EL1 value that identifies it within the processor's affinity hierarchy. On a typical ARM laptop SoC, MPIDR encodes Aff0 (core within cluster), Aff1 (cluster number), Aff2 (higher-level grouping). AETHER reads the MPIDR of each core during boot to build its inventory. When assigning cores to guests, AETHER must present each guest with a contiguous, valid-looking MPIDR space — guests should not see gaps in their core numbering.

**PSCI — The Guest's Only Way To Manage CPUs.** When an operating system wants to start a secondary CPU core, it does not directly write hardware registers — it calls PSCI via HVC (hypervisor call) or SMC (secure monitor call). PSCI defines a standard interface: CPU_ON(target_affinity, entry_point, context_id) to start a core, CPU_OFF() to stop the current core, CPU_SUSPEND() for power management. AETHER traps these calls (via HVC trapping enabled in HCR_EL2) and decides whether to honor them. For cores assigned to the calling guest, AETHER starts the core at EL1 in the guest's context. For cores assigned to the other guest, AETHER returns PSCI_DENIED.

**Static Partitioning Has No Scheduler.** Unlike a conventional hypervisor that time-multiplexes CPUs across VMs, AETHER assigns each physical core permanently to one guest for the duration of the session. There is no scheduling, no context switching between guests on a single core, no AETHER-managed timer interrupt to preempt a guest. A guest's assigned cores run that guest exclusively. This simplicity is a feature: it eliminates scheduling overhead, eliminates cache thrashing from cross-guest scheduling, and makes timing characteristics indistinguishable from native hardware.

**Core Affinity And Interrupt Routing.** The GIC uses affinity routing (enabled by GICD_CTLR.ARE_S=1) to direct SPIs (Shared Peripheral Interrupts) to specific cores using GICD_IROUTER registers. AETHER must configure GICD_IROUTER for each device's interrupt such that Android-assigned device interrupts are routed only to Android-assigned cores, and Windows-assigned device interrupts route only to Windows-assigned cores. A misconfigured GICD_IROUTER that sends an Android device's interrupt to a Windows core would cause Windows to handle it (with wrong driver) or fault.

**Presenting A Coherent Core Count To Each Guest.** When a guest reads the system topology — through MPIDR, through ACPI MADT table, through device tree — it must see only its assigned cores. AETHER accomplishes this through the synthesized ACPI tables presented to each guest (Chapter 18) and by trapping reads of topology-revealing registers where necessary.

## Common AI Mistakes In This Domain

Claude generates PSCI emulation that honors CPU_ON requests without checking whether the requested affinity belongs to the calling guest. This allows a guest to start cores that belong to the other guest.

Claude confuses Aff0 and Aff1 fields in MPIDR when doing affinity comparisons, producing core assignment logic that works on single-cluster chips but fails on multi-cluster designs like the Snapdragon X Elite.

Claude generates interrupt routing code that uses a simple core number rather than the GICD_IROUTER format, which expects affinity values not linear core indices.

## Verification Protocol

For PSCI emulation code:
1. Verify that CPU_ON checks the requested affinity against the calling guest's assigned core list before proceeding
2. Verify that CPU_ON returns PSCI_DENIED (0xFFFFFFFF8) for cores belonging to the other guest
3. Verify that the entry point address from CPU_ON is mapped in the guest's Stage 2 tables before jumping there

For interrupt routing code:
1. Verify GICD_IROUTER format against GIC spec Section 4.8
2. Verify that every device interrupt is routed to its owning guest's core affinity range
3. Verify GICD_CTLR.ARE_S=1 is set before affinity routing is configured

## Pre-Flight Checklist

- [ ] Download PSCI spec `DEN0022` and read completely — it is short (~50 pages)
- [ ] Read ARM ARM Section D1.8 on multiprocessing
- [ ] Study `arch/arm64/kvm/psci.c` — understand every PSCI function KVM implements
- [ ] Study `arch/arm64/kernel/smp.c` — understand what a guest kernel does when it starts secondary cores
- [ ] List all cores on the target Snapdragon X Elite hardware with their MPIDR values and cluster assignments before writing any partitioning code
