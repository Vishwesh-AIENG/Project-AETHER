# SKILL.md — Chapter 13: GPU Partitioning Through SR-IOV

## Confidence Disclosure

**LOW for Adreno-specific details, MEDIUM for SR-IOV concepts generally, NONE for Adreno command stream format.** GPU virtualization is the most vendor-specific, most NDA-protected area of the entire project. Adreno GPU internals are not publicly documented to the level needed for full implementation. AETHER's GPU strategy depends on SR-IOV at the hardware level, which means AETHER itself does not need to understand the command stream — it just partitions the hardware. But driver integration on the Android side requires Adreno driver knowledge.

## Required Primary Sources

**PCI Express Base Specification, Chapter 6** — SR-IOV specification. The authoritative definition of how SR-IOV physical functions (PFs) and virtual functions (VFs) work, how VFs are enumerated, and how the PCIe topology looks to software.

**Qualcomm Snapdragon X Elite Technical Reference Manual** — Requires NDA with Qualcomm. This is unavoidable for Adreno-specific work. Without it, Adreno SR-IOV configuration must be reverse-engineered from open-source driver code.

**Linux DRM (Direct Rendering Manager) documentation** at `Documentation/gpu/` in the kernel tree — General GPU subsystem documentation. Particularly `drm-kms.md` and `amdgpu.rst` (as a well-documented example of SR-IOV GPU virtualization).

## Secondary Sources

**Freedreno** at gitlab.freedesktop.org/mesa/mesa (in `src/freedreno/`) — The open-source Adreno driver reverse-engineered by Rob Clark and contributors. Contains the most complete publicly available documentation of Adreno GPU register spaces, command stream format, and memory management. This is AETHER's primary reference for Adreno-specific details in the absence of Qualcomm documentation.

**Mesa Turnip** at the same Mesa repository in `src/freedreno/vulkan/` — The open-source Vulkan driver for Adreno. Its initialization sequence reveals SR-IOV-adjacent GPU resource management.

**AMDGPU SR-IOV implementation** at `drivers/gpu/drm/amd/amdgpu/` — AMD's GPU SR-IOV is the best-documented open-source GPU virtualization implementation. Not Adreno-specific but the architectural patterns transfer.

**Intel GVT-g** at `drivers/gpu/drm/i915/gvt/` — Intel's mediated GPU passthrough. Another reference for GPU virtualization patterns.

## Critical Concepts

**SR-IOV Physical Function And Virtual Functions.** SR-IOV splits a single PCIe device into one Physical Function (PF) and multiple Virtual Functions (VFs). The PF is the real device, used by the host/hypervisor for configuration. VFs are lightweight instances that each appear as a separate PCIe device with their own BARs, interrupts, and DMA address space. For GPU SR-IOV, each VF gets its own partition of the GPU's execution resources — shader cores, texture units, command queues, and video memory. The GPU hardware enforces isolation between VF partitions.

**VF Enumeration.** AETHER reads the SR-IOV capability from the GPU's PCIe configuration space to determine how many VFs can be created. It then enables SR-IOV (via the SR-IOV Extended Capability's `NumVFs` and `VF Enable` fields) to instantiate the VFs. Each VF appears as a new PCIe device in the topology with its own BUS:DEV:FUNC address. AETHER assigns VF 0 to Windows and VF 1 to Android (or vice versa).

**VRAM Partitioning.** Video RAM is the GPU's dedicated memory. SR-IOV partitions VRAM between VFs so each VF sees only its allocated portion. The VRAM partition sizes are configured through PF registers before VFs are enabled. For AETHER with two guests, VRAM is split roughly in proportion to the guests' expected graphics workloads — gaming in Android might warrant a 75/25 split favoring Android.

**Driver Matching.** The Android partition needs a kernel driver for the Adreno VF. The Freedreno driver in the Linux kernel (`drivers/gpu/drm/msm/`) is the starting point. It may require modification to handle VF-specific initialization rather than PF initialization. This is where Qualcomm NDA documentation becomes essential — VF initialization sequences are not fully documented in open sources.

**ANGLE For OpenGL ES.** Android apps use OpenGL ES. The Android graphics stack translates OpenGL ES to Vulkan internally (via ANGLE or the Android GLES-over-Vulkan path), and then Vulkan commands go to the Adreno Vulkan driver (Turnip or the proprietary driver). AETHER does not need to handle this translation — it happens entirely within the Android partition's userspace graphics stack. AETHER only needs to ensure the Adreno VF is correctly assigned and accessible.

## Common AI Mistakes In This Domain

Claude invents Adreno register addresses and command stream formats. There is no reliable public documentation for these — any specific numbers Claude produces for Adreno-specific configuration should be treated as fabricated until verified against Freedreno source or Qualcomm documentation.

Claude confuses PF and VF initialization sequences. PF initialization is done by AETHER (the hypervisor). VF initialization is done by the guest's GPU driver. Conflating these produces code that tries to perform PF operations from the guest context, which is blocked by SR-IOV isolation.

Claude generates GPU memory barrier code using x86 equivalents (`mfence`, `sfence`) rather than ARM64 memory barrier instructions.

## Verification Protocol

For SR-IOV enumeration code:
1. Verify PCIe capability structure offsets against PCI Express spec Chapter 6
2. Verify VF BAR sizes and alignment requirements before mapping them into guest address spaces
3. Test VF enumeration on real hardware — verify the correct number of VFs appears in the PCIe topology

For Adreno-specific code:
1. Cross-reference every register address against Freedreno source at `src/freedreno/registers/`
2. Where Freedreno source conflicts with Claude's output, Freedreno is correct
3. Test every GPU operation in a controlled environment (QEMU with VirtIO GPU as a fallback) before testing on real Adreno hardware

## Pre-Flight Checklist

- [ ] Read PCI Express spec Chapter 6 on SR-IOV completely
- [ ] Clone Mesa and study `src/freedreno/` extensively — this is your primary Adreno reference
- [ ] Study `drivers/gpu/drm/msm/` in the Linux kernel — the Adreno DRM driver
- [ ] Contact Qualcomm's developer relations team about documentation access for Snapdragon X Elite GPU
- [ ] Study AMDGPU SR-IOV (`drivers/gpu/drm/amd/amdgpu/amdgpu_virt.c`) as an architectural reference
- [ ] Test SR-IOV enumeration on the target hardware using Linux before implementing in AETHER
