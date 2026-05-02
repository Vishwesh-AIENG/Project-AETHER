# SKILL.md — Chapter 6: The Virtualization Extensions

## Confidence Disclosure

**LOW.** This is the chapter where Claude's training is most dangerously sparse relative to its confidence level. The ARM virtualization extensions involve dozens of interacting system registers, a specific initialization sequence that must be exact, and hardware behaviors that are only fully described in the ARM ARM. Claude will produce structurally plausible EL2 initialization code that silently does the wrong thing. This chapter requires the most primary source verification of any in the project.

## Required Primary Sources

**ARM ARM `DDI0487`:**

| Section | Topic | Priority |
|---|---|---|
| Section D5.5 | Stage 2 translation | MANDATORY — read every page |
| Section D5.6 | VMID and Address Space IDs | Read completely |
| Section G4 | Virtualization Host Extensions (VHE) | Read completely |
| Section D1.16 | Hypervisor Call (HVC) exception | Read completely |
| Section G5 | EL2 system registers | Use as reference |
| Section H4 | GIC Virtualization Extensions | Read completely |

**ARM GIC Architecture Specification v3/v4 `IHI0069`:**

| Section | Topic | Priority |
|---|---|---|
| Chapter 8 | GIC Virtualization | MANDATORY |
| Section 8.1–8.4 | Virtual interrupt injection via List Registers | Critical |
| Section 8.6 | ICH_LR registers | Critical — read every bit field |

## Secondary Sources

**Linux KVM ARM64 source** at `arch/arm64/kvm/`:
- `hyp/include/nvhe/` — nVHE (non-VHE) hypervisor headers
- `hyp/nvhe/setup.c` — EL2 initialization sequence
- `hyp/nvhe/switch.c` — Guest entry/exit
- `arm.c` — Top-level KVM ARM implementation

**Xen on ARM source** at `xen/arch/arm/`:
- `setup.c` — EL2 initialization
- `vgic-v3.c` — Virtual GIC implementation

## Critical Concepts

**VHE vs nVHE.** The ARM Virtualization Host Extensions (VHE), enabled by setting HCR_EL2.E2H=1, allow the hypervisor to run in EL2 while presenting itself as EL1 to the rest of the system. This simplifies hypervisor development by allowing direct use of EL1-addressed system registers. AETHER should target nVHE (HCR_EL2.E2H=0), the traditional model, because it provides stronger isolation between the hypervisor and guests. KVM's nVHE implementation is the closest reference.

**HCR_EL2 — The Hypervisor Configuration Register.** This is the most important register in the virtualization architecture. Its bits control which guest operations trap to EL2, whether Stage 2 translation is enabled, the security state of EL1/EL0, and many other behaviors. The critical bits are:
- `VM` (bit 0): enable Stage 2 translation — must be 1 for guests
- `FMO` (bit 3): route FIQ to EL2
- `IMO` (bit 4): route IRQ to EL2
- `AMO` (bit 5): route SError to EL2
- `TWI` (bit 13): trap WFI to EL2
- `TWE` (bit 14): trap WFE to EL2
- `TVM` (bit 26): trap virtual memory system register accesses
- `RW` (bit 31): lower exception level is AArch64

Claude frequently gets HCR_EL2 bit assignments wrong. Always verify every bit against ARM ARM Section G5.

**VTCR_EL2 — Virtualization Translation Control Register.** Controls Stage 2 translation parameters: the VMID size (8-bit or 16-bit), the translation granule (4KB/16KB/64KB), and the address space size. The T0SZ field determines how many bits of the IPA are used as the input to Stage 2 translation. Getting T0SZ wrong produces a Stage 2 address space that is either too small (rejects valid guest addresses) or too large (wastes memory on page tables).

**VTTBR_EL2 — Virtualization Translation Table Base Register.** Points to the root of the Stage 2 page table tree. Contains both the physical address of the table and the VMID (Virtual Machine ID) that tags TLB entries for this guest. When switching between guests (even during initialization), VTTBR_EL2 must be updated and the TLB must be invalidated appropriately.

**Stage 2 Descriptor Format.** This is where Claude is most likely to produce wrong output. Stage 2 descriptors are NOT the same as Stage 1 descriptors. The attribute bits are different, the permission model is different, and the memory type encoding uses a different system (S2AP instead of AP, MemAttr instead of AttrIndx). Critically:
- Stage 2 uses a 2-bit S2AP field for access permissions (R/W control for EL1 and EL0 separately)
- Stage 2 uses a 4-bit MemAttr field for memory attributes (not the MAIR_EL1 table)
- Stage 2 uses HAP bits for hardware access flag management

**VMID — Virtual Machine Identifier.** Every guest has a VMID stored in VTTBR_EL2. TLB entries are tagged with VMIDs so that different guests' translations don't interfere. VMID space is either 8-bit (256 VMIDs) or 16-bit (65536 VMIDs). AETHER with two guests only needs two VMIDs, but the VMID field size must be configured consistently in VTCR_EL2 and the TLB invalidation instructions must use the correct VMID.

**Virtual Interrupt Injection — List Registers.** The GIC virtualization extension provides a set of List Registers (ICH_LR0_EL2 through ICH_LR15_EL2) that the hypervisor programs to inject virtual interrupts into a guest. Each LR contains a virtual interrupt ID, a physical interrupt ID (for hardware-routed interrupts), and state bits. The hypervisor programs these before entering a guest, and the hardware delivers the virtual interrupts to the guest's vCPU via the virtual CPU interface (GICV). Claude understands the concept but gets the LR bit field layout wrong — always verify against GIC spec Section 8.

## Common AI Mistakes In This Domain

Claude produces HCR_EL2 initialization values with incorrect bit positions. This causes either missing traps (security holes) or spurious traps (performance problems and crashes).

Claude generates Stage 2 page table descriptors using Stage 1 attribute encoding. The tables build without error and the MMU walks them, but the memory type and permission bits are interpreted differently, producing wrong caching behavior or access faults.

Claude omits VMID tagging in VTTBR_EL2, which causes TLB conflicts between guests on cores where both guests have run.

Claude generates TLB invalidation sequences that are insufficient — missing the required DSB before and ISB after invalidation instructions.

Claude confuses TLBI ALLE2 (invalidate all EL2 TLB entries) with TLBI VMALLS12E1 (invalidate all Stage 1 and Stage 2 TLB entries for the current VMID). Using the wrong invalidation instruction leaves stale translations.

## Verification Protocol

For EL2 initialization code:
1. Check every bit of HCR_EL2 against ARM ARM Table G4-1
2. Verify VTCR_EL2 T0SZ and TG0 fields produce the intended address space size and granule
3. Confirm VTTBR_EL2 contains both the correct physical address (bits [47:1] or [51:1] depending on PA size) and the correct VMID

For Stage 2 page table code:
1. Verify every attribute bit against ARM ARM Section D5.5.4 (Stage 2 memory attribute fields)
2. Confirm S2AP encoding matches ARM ARM Table D5-50
3. Confirm MemAttr encoding matches ARM ARM Table D5-51

For interrupt injection code:
1. Verify ICH_LR layout against GIC spec Section 8.4.5
2. Confirm vINTID and pINTID ranges are valid for the configured GIC
3. Verify the List Register state machine (Pending → Active → Invalid) is correctly implemented

## Pre-Flight Checklist

- [ ] Read ARM ARM Section D5.5 (Stage 2 translation) in full — approximately 40 pages
- [ ] Read ARM ARM Section G4 (VHE) — understand why AETHER chooses nVHE
- [ ] Read GIC spec Chapter 8 in full
- [ ] Study `arch/arm64/kvm/hyp/nvhe/setup.c` — trace every register write in the EL2 setup sequence
- [ ] Run KVM on an ARM64 machine (QEMU works) and use perf to observe VM exits — understand what triggers them before implementing the handler
- [ ] Write a program that sets HCR_EL2 and intentionally causes a specific trap (e.g., HVC from EL1) and handles it at EL2 — verify ESR_EL2 contains what you expect
