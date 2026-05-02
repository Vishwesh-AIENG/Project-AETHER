# SKILL.md — Chapter 11: The Passthrough Principle

## Confidence Disclosure

**MEDIUM conceptually, LOW for PCIe/SMMU implementation specifics.** The principle itself is well understood. The implementation details of PCIe device assignment — IOMMU group handling, BAR remapping, MSI/MSI-X interrupt assignment — require primary source verification. Mistakes here produce either devices that don't work (best case) or devices that corrupt memory across partition boundaries (worst case).

## Required Primary Sources

**PCI Express Base Specification** (latest, available partially through pcisig.com):

| Section | Topic | Priority |
|---|---|---|
| Chapter 2 | Transaction Layer | Read for TLP (Transaction Layer Packet) concepts |
| Chapter 6 | SR-IOV | Critical for GPU and NIC passthrough |
| Section 6.7 | ARI (Alternative Routing-ID Interpretation) | Read with SR-IOV |

**ARM SMMU v3 Specification `IHI0070`:**
- Section 3.4: Stream table format — how PCIe devices are identified to the SMMU
- Section 3.6: MSI mapping — how MSI interrupts work through the SMMU

**Linux VFIO documentation** at `Documentation/driver-api/vfio.rst` in the kernel tree — VFIO is Linux's mechanism for userspace device passthrough and is the most mature open-source implementation of the exact concepts AETHER uses.

## Secondary Sources

**Linux VFIO source** at `drivers/vfio/` — The reference implementation for device assignment.

**Linux IOMMU group handling** at `drivers/iommu/iommu.c` — How Linux manages IOMMU groups, which is critical for understanding why some devices can and cannot be separated from each other for passthrough.

**Xen device passthrough** at `xen/drivers/passthrough/arm/` — ARM-specific device passthrough in Xen.

## Critical Concepts

**IOMMU Groups.** The IOMMU does not isolate individual PCIe functions — it isolates IOMMU groups. An IOMMU group is the set of PCIe functions that share DMA resources and therefore cannot be separated for independent assignment. On most platforms, a single PCIe device (physical function) and all its SR-IOV virtual functions form one IOMMU group. Before assigning a device to a guest, AETHER must verify that all functions in its IOMMU group are assigned to the same guest. Assigning half an IOMMU group to Android and half to Windows would break DMA isolation.

**BAR Remapping.** PCIe devices have Base Address Registers (BARs) that describe the memory and I/O address ranges the device uses for MMIO. In a passthrough configuration, the device's BAR addresses must be remapped so they fall within the guest's physical address space. This is done through Stage 2 translation — AETHER creates Stage 2 mappings that translate the guest's view of the BAR addresses to the actual physical addresses the device is programmed with. If the BAR addresses happen to fall outside the guest's IPA range, the device cannot be passed through without firmware cooperation to relocate the BARs.

**MSI And MSI-X Interrupt Passthrough.** Modern PCIe devices use MSI or MSI-X for interrupts rather than legacy INTx lines. MSI works by writing to a specific memory address (the MSI address) to signal an interrupt. In a virtualized environment, the SMMU must be configured to recognize MSI writes from assigned devices and route them to the appropriate guest through the virtual GIC. This requires MSI address mapping in the SMMU's MSI table — a feature added in SMMU v3. Claude frequently omits MSI configuration when generating device passthrough code, producing devices that initialize successfully but never deliver interrupts.

**Device Reset.** When a guest is reset or a device is reassigned, the device must be reset to a clean state. Unclean device state from a previous guest session can cause the new guest's driver to malfunction or, worse, allow a new guest to access DMA buffers still programmed with the previous guest's memory addresses. PCIe function-level reset (FLR) is the mechanism for this — AETHER must trigger FLR before assigning a device to any guest.

## Common AI Mistakes In This Domain

Claude generates passthrough configurations that ignore IOMMU group boundaries, assigning devices that share an IOMMU group to different guests.

Claude generates SMMU stream table entries for passed-through devices that use bypass mode instead of translated mode, effectively disabling DMA isolation for those devices.

Claude omits device reset (FLR) between guest sessions.

Claude generates code that accesses device BARs at their physical addresses rather than through guest-visible mappings, creating a hypervisor-visible side channel.

## Verification Protocol

For device assignment code:
1. Verify that all functions in the device's IOMMU group are assigned to the same guest
2. Verify SMMU STE is in translation mode (not bypass) for every assigned device
3. Verify FLR is performed before device assignment
4. Verify MSI address mapping in the SMMU MSI table

## Pre-Flight Checklist

- [ ] Read Linux VFIO documentation fully
- [ ] Study `drivers/vfio/pci/vfio_pci_core.c` — understand the device assignment lifecycle
- [ ] Read PCI Express Chapter 6 on SR-IOV
- [ ] On a test machine, use Linux VFIO to pass a real device to a QEMU guest — understand the userspace steps before implementing them in a hypervisor
- [ ] List all devices on the target Snapdragon X Elite hardware with their IOMMU group memberships before designing the partitioning scheme
