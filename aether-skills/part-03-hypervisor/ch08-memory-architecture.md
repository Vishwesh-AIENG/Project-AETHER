# SKILL.md — Chapter 8: Memory Architecture

## Confidence Disclosure

**LOW — the highest-risk chapter in the entire project.** Memory isolation is the foundational security guarantee of AETHER. A single wrong bit in a Stage 2 descriptor, a single missing SMMU stream table entry, a single incorrect TLB invalidation — any one of these can silently allow one guest to read or write another guest's memory. The failure is not a crash. It is a silent security violation that appears to work correctly. Claude has conceptual knowledge of two-stage translation but gets descriptor-level details wrong at a rate that makes unverified AI-generated code dangerous here.

## Required Primary Sources

**ARM ARM `DDI0487`:**

| Section | Topic | Priority |
|---|---|---|
| Section D5.1 | About the AArch64 Virtual Memory System | Read first |
| Section D5.2 | Translation table formats | MANDATORY |
| Section D5.3 | Memory attribute fields | MANDATORY |
| Section D5.4 | Stage 1 translation | Read for comparison |
| Section D5.5 | Stage 2 translation | MANDATORY — most critical section |
| Section D5.6 | The VMIDDs | Read completely |
| Section D5.10 | TLB maintenance instructions | MANDATORY |
| Section D5.11 | Cache maintenance instructions | Read completely |
| Table D5-22 | Stage 2 memory attribute encoding | Memorize this table |

**ARM SMMU Architecture Specification v3 `IHI0070`:**

| Section | Topic | Priority |
|---|---|---|
| Chapter 1 | Introduction | Read |
| Chapter 3 | Functional Description | MANDATORY |
| Section 3.4 | Stream tables | Critical |
| Section 3.5 | Context descriptors | Critical |
| Chapter 6 | Register interface | Reference |

## Secondary Sources

**Linux kernel SMMU driver** at `drivers/iommu/arm/arm-smmu-v3/arm-smmu-v3.c` — The most complete open-source SMMU v3 implementation. Study how it initializes the SMMU, how it constructs stream table entries (STEs), and how it maps IOVA to PA for device DMA.

**Linux kernel `arch/arm64/mm/`** — Stage 1 page table management. Illuminates the same concepts as Stage 2, which helps build intuition.

**KVM ARM Stage 2** at `arch/arm64/kvm/mmu.c` — The KVM Stage 2 implementation. This is the closest reference for what AETHER's Stage 2 manager must do.

**Xen on ARM memory management** at `xen/arch/arm/mm.c` — Alternative reference implementation.

## Critical Concepts

**Three Layers Of Translation — Again, In Depth.** The README introduces this concept. Here is the implementation-level detail. When the Android guest's CPU issues a load instruction at virtual address VA, the MMU first walks the Stage 1 tables (managed by the Android Linux kernel, rooted at TTBR0_EL1 or TTBR1_EL1) to produce an Intermediate Physical Address (IPA). The MMU then walks the Stage 2 tables (managed by AETHER, rooted at VTTBR_EL2) to produce the true Physical Address (PA). Both walks happen transparently in hardware. If either walk fails to find a valid mapping, a fault is taken to the appropriate exception level. AETHER's Stage 2 tables define what physical memory Android can reach, period.

**Stage 2 Descriptor Bit Fields — Exact Layout.** For a 4KB granule, a Stage 2 block descriptor at level 2 (mapping 2MB blocks) has:
- Bits [1:0]: type — 01 for block, 11 for table, 00/10 for invalid
- Bits [11:2]: lower attributes
  - Bits [5:2]: MemAttr (4-bit memory type, see Table D5-22)
  - Bits [7:6]: S2AP (Stage 2 Access Permissions, 00=none, 01=RO, 10=WO, 11=RW)
  - Bits [9:8]: SH (Shareability)
  - Bit [10]: AF (Access Flag)
  - Bit [11]: nG (not global, always 0 for Stage 2)
- Bits [47:12] (or [51:12] for 52-bit PA): Output address
- Bits [63:52]: upper attributes
  - Bit [54]: XN (execute-never for EL1)
  - Bit [53]: PXN (privileged execute-never for EL0 within guest)
  - Bit [51]: DBM (dirty bit modifier)

Claude frequently gets MemAttr encoding wrong. The correct values are in ARM ARM Table D5-22 and are entirely different from Stage 1's AttrIndx approach.

**The SMMU Stream Table.** Every DMA-capable device connected to the SMMU is identified by a StreamID — a number derived from the device's position in the PCIe topology or AMBA bus. The SMMU maintains a Stream Table where each StreamID indexes a Stream Table Entry (STE). The STE controls whether the device's DMA transactions are translated (using a Stage 2 page table referenced from the STE), bypassed, or faulted. AETHER must configure the SMMU stream table so that every device assigned to Android uses Stage 2 page tables that restrict its DMA to Android's memory, and every device assigned to Windows uses Windows's memory range.

**The Linear Map.** AETHER's own address space (at EL2) needs a mapping of all physical memory for its own internal use — to manipulate page tables, write configuration data, etc. This is called the linear map: a contiguous virtual address range in EL2 that maps all of physical memory with a fixed offset. Linux calls its version of this the "direct map." AETHER needs its own version so that given any physical address, AETHER can compute a virtual address it can dereference. Managing this linear map correctly is subtle — it must never overlap with the regions assigned to guests.

**TLB Invalidation Is Not Optional.** When AETHER modifies a Stage 2 page table entry — changing a permission, remapping a region, removing a mapping — the old translation may still be cached in the TLB. Any access by the guest after the table modification but before TLB invalidation uses the old (potentially incorrect) translation. AETHER must invalidate TLB entries using the correct TLBI instruction with the correct operands (VMID, ASID, address range) and must bracket the invalidation with DSB instructions to ensure ordering.

## Common AI Mistakes In This Domain

Claude generates Stage 2 descriptors using Stage 1 attribute encoding. The MemAttr field in Stage 2 is encoded completely differently from AttrIndx in Stage 1. Code that looks syntactically correct produces wrong memory attributes.

Claude omits AF (Access Flag) bits in descriptors. On hardware that uses hardware-managed access flags, omitting AF causes an immediate fault on first access. On hardware requiring software-managed access flags, the AF must be set explicitly in initial mappings.

Claude generates SMMU stream table entries with incorrect format fields. The STE format changed between SMMU v2 and v3; Claude conflates them.

Claude generates TLB invalidation code without the required surrounding DSB instructions, producing code that works most of the time but has rare race-condition failures that are almost impossible to debug.

Claude miscalculates the number of page table levels required for a given address space size and granule. Use the formula from ARM ARM Section D5.2: number of levels = ceil((input_address_bits - granule_bits) / (granule_bits - 3)).

## Verification Protocol

For Stage 2 page table code:
1. Verify every descriptor bit field against ARM ARM Table D5-22 and surrounding tables
2. Verify the granule and T0SZ settings in VTCR_EL2 match the table layout the code produces
3. Write a test that maps a known region, accesses it from a test guest, verifies the access succeeds, then removes the mapping and verifies the access faults — run in QEMU

For SMMU code:
1. Verify STE format against SMMU spec Section 6.3
2. Verify CD (Context Descriptor) format against SMMU spec Section 6.4
3. Verify that every DMA-capable device has an STE — devices without STEs default to bypass, which is a security hole

For TLB invalidation:
1. Verify every TLBI instruction operand against ARM ARM Section D5.10
2. Verify DSB precedes and follows every TLBI sequence
3. On multi-core systems, verify that TLBI uses the IS (inner-shareable) suffix to broadcast to all cores in the guest's assigned set

## Pre-Flight Checklist

- [ ] Read ARM ARM Section D5 in full — all of it, not just the Stage 2 parts
- [ ] Read SMMU v3 spec Chapters 3 and 6
- [ ] Draw the complete address translation flow for a single guest memory access — every arrow from VA to IPA to PA, with the registers involved at each step
- [ ] Study `arch/arm64/kvm/mmu.c` — understand every function's purpose before writing any equivalent AETHER code
- [ ] Study `drivers/iommu/arm/arm-smmu-v3/` — particularly how stream table entries are constructed
- [ ] Implement a minimal Stage 2 mapping in QEMU that maps exactly 1GB for a test guest, verify the guest can read/write that GB but faults on anything outside it
- [ ] Create a reference table of all TLBI instructions AETHER will use and exactly what they invalidate
