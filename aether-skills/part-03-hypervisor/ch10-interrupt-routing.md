# SKILL.md — Chapter 10: Interrupt Routing

## Confidence Disclosure

**LOW.** GICv3/v4 virtual interrupt injection is one of the most intricate subsystems in ARM virtualization. Claude understands the concept but gets List Register bit fields wrong, confuses physical and virtual interrupt IDs, and mishandles the state machine for interrupt lifecycle. The GIC spec is the only authoritative source — treat all Claude output in this chapter as a draft requiring line-by-line verification.

## Required Primary Sources

**ARM GIC Architecture Specification v3 and v4 `IHI0069`** — This is the primary document for this entire chapter. Read it fully before writing any interrupt routing code.

| Section | Topic | Priority |
|---|---|---|
| Chapter 2 | GIC overview and concepts | Read first |
| Chapter 3 | Distributor (GICD) | Essential |
| Chapter 4 | Redistributor (GICR) | Essential |
| Chapter 5 | CPU interface (ICC) | Essential |
| Chapter 8 | Virtualization | MANDATORY — the core of this chapter |
| Section 8.1 | Virtual CPU interface (GICV) | Critical |
| Section 8.2 | Hypervisor control interface (GICH) | Critical |
| Section 8.4 | ICH_LR registers | Memorize the bit layout |
| Section 8.6 | Maintenance interrupts | Read completely |

**ARM ARM `DDI0487`** Section D1.13–D1.14 on interrupt handling as background.

## Secondary Sources

**Linux KVM GICv3 virtual implementation** at `virt/kvm/arm/vgic/vgic-v3.c` — The most tested open-source virtual GIC v3 implementation. Study how KVM programs List Registers, handles maintenance interrupts, and manages the physical-to-virtual interrupt mapping.

**Xen GIC v3 implementation** at `xen/arch/arm/gic-v3.c` — Alternative reference.

**Linux GICv3 driver** at `drivers/irqchip/irq-gic-v3.c` — Shows how real GICv3 hardware is initialized, which informs how AETHER must initialize the physical GIC before presenting a virtual GIC to guests.

## Critical Concepts

**GICv3 Topology.** A GICv3 system has one Distributor (GICD) shared across all cores, one Redistributor (GICR) per core, and one CPU Interface (ICC) per core accessed via system registers (not memory-mapped in v3). Shared Peripheral Interrupts (SPIs, INTID 32–1019) are managed by the Distributor. Private Peripheral Interrupts (PPIs, INTID 16–31) and Software Generated Interrupts (SGIs, INTID 0–15) are managed per-core by the Redistributor. AETHER must initialize all of these for the physical GIC, then present a virtual GIC to each guest.

**Virtual CPU Interface And Hypervisor Control Interface.** The GICv3 virtualization extension adds two new interfaces. The Hypervisor Control Interface (accessed via ICH_* system registers at EL2) is used by AETHER to program virtual interrupt delivery. The Virtual CPU Interface (GICV, a memory-mapped region) is what the guest kernel uses to acknowledge and end virtual interrupts — it looks to the guest like a real CPU interface. AETHER maps GICV into each guest's address space so the guest's GIC driver works without modification.

**List Registers — ICH_LR0_EL2 through ICH_LR15_EL2.** These are the mechanism for injecting virtual interrupts. Each LR contains one pending or active virtual interrupt. The bit layout is:
- Bits [63:62]: State — 00=Invalid, 01=Pending, 10=Active, 11=Active+Pending
- Bit [61]: HW — 1 if this is a hardware interrupt (physical interrupt is linked)
- Bit [60]: Group — 1 for Group 1 (IRQ), 0 for Group 0 (FIQ)
- Bits [59:56]: Priority of the virtual interrupt
- Bits [44:32]: pINTID — physical interrupt ID (only valid when HW=1)
- Bits [31:0]: vINTID — virtual interrupt ID the guest will see

When HW=1, the GIC hardware automatically deactivates the physical interrupt when the guest deactivates the virtual one — the hypervisor does not need to intervene. When HW=0, AETHER must handle deactivation manually via a maintenance interrupt.

**Maintenance Interrupts.** When a virtual interrupt is deactivated by the guest, and HW=0, the GIC generates a maintenance interrupt to EL2. AETHER's maintenance interrupt handler must identify which virtual interrupt was deactivated, perform any necessary cleanup (re-enabling the physical interrupt if needed), and remove the LR entry. The ICH_MISR_EL2 register identifies the reason for the maintenance interrupt.

**Priority, Preemption, And Priority Masks.** The GIC has a complex priority system. Interrupts with numerically lower priority values have higher priority. The CPU interface has a priority mask register (ICC_PMR_EL1) that blocks interrupts below a certain priority. The running priority register (ICC_RPR_EL1) tracks the priority of the currently active interrupt. The binary point register controls preemption grouping. All of these exist in both physical and virtual forms and must be correctly presented to each guest.

## Common AI Mistakes In This Domain

Claude generates ICH_LR values with the State field in the wrong bit positions. The State field is bits [63:62] in GICv3, not bits [61:60]. Using wrong bit positions means interrupts are never delivered.

Claude confuses vINTID and pINTID placement within the LR. Swapping them causes the guest to receive wrong interrupt IDs or causes hardware deactivation to fail silently.

Claude omits the ICH_HCR_EL2.EN bit (enable bit for the virtual CPU interface). Without this set, virtual interrupts are never delivered regardless of LR programming.

Claude generates interrupt routing code that doesn't account for the difference between level-sensitive and edge-triggered interrupts in the context of virtual interrupt injection. Level-sensitive interrupts that are not EOI'd by the guest remain active indefinitely.

Claude often forgets to initialize GICR (Redistributors) per-core before initializing the GICD (Distributor). The GIC spec requires Redistributors to be initialized first.

## Verification Protocol

For List Register programming code:
1. Verify every bit field against GIC spec Section 8.4 — bit by bit, field by field
2. Verify ICH_HCR_EL2.EN=1 is set before any interrupt injection attempt
3. Verify that HW=1 LRs have a valid pINTID that corresponds to the physical interrupt being forwarded
4. Write a test that injects a software-generated virtual interrupt (vSGI) and verifies the guest receives it at the correct vINTID

For maintenance interrupt handling:
1. Verify ICH_MISR_EL2 bit meanings against GIC spec Section 8.6
2. Verify that all maintenance interrupt conditions are handled — not just EOI maintenance

For physical GIC initialization:
1. Verify GICD initialization sequence against GIC spec Chapter 3, particularly the enable sequence
2. Verify GICR initialization for each core before GICD enable

## Pre-Flight Checklist

- [ ] Download GIC Architecture Specification `IHI0069` and read Chapters 2–5 and 8 fully
- [ ] Study `virt/kvm/arm/vgic/vgic-v3.c` — map every function to a concept in the GIC spec
- [ ] Study `drivers/irqchip/irq-gic-v3.c` for physical initialization reference
- [ ] In QEMU with GICv3 emulation, trace all GIC register accesses during Linux boot — understand the initialization sequence Linux expects
- [ ] Draw the complete interrupt delivery path: physical device → GIC Distributor → GIC Redistributor → List Register → virtual CPU interface → guest kernel ISR
- [ ] Implement a minimal virtual GIC in QEMU that can deliver a single timer interrupt to a test guest before touching AETHER's real GIC code
