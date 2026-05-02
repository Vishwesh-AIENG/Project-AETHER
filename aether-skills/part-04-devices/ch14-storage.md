# SKILL.md — Chapter 14: Storage Partitioning

## Confidence Disclosure

**MEDIUM.** NVMe is a well-documented public specification and Claude has reasonable knowledge of it. The specific implementation details of NVMe namespace isolation and SR-IOV on NVMe controllers require verification, as these are newer features with less training coverage.

## Required Primary Sources

**NVM Express Base Specification** (latest revision, free at nvmexpress.org):

| Section | Topic | Priority |
|---|---|---|
| Chapter 1 | Introduction and overview | Read first |
| Chapter 3 | Command set | Essential |
| Chapter 8 | Namespaces | MANDATORY |
| Section 8.1 | Namespace management | Critical |
| Section 8.2 | Namespace sharing | Critical |
| Chapter 9 | SR-IOV for NVMe | Read completely |

**NVM Express I/O Command Set Specification** — companion to base spec, covers the actual read/write command formats.

## Secondary Sources

**Linux NVMe driver** at `drivers/nvme/host/` — Reference implementation of NVMe host driver. Particularly `core.c` and `pci.c` for PCI NVMe initialization.

**Linux NVMe target** at `drivers/nvme/target/` — The NVMe target implementation is useful for understanding namespace isolation from the device perspective.

**QEMU NVMe device emulation** at `hw/block/nvme.c` in QEMU source — Shows how NVMe namespaces are implemented in software, which informs AETHER's namespace management design.

## Critical Concepts

**NVMe Namespaces.** An NVMe namespace is a logical partition of an NVMe SSD's storage capacity. Each namespace has its own Namespace ID (NSID), its own size in logical blocks, and its own format. From the host's perspective, each namespace looks like a separate block device. Crucially, namespaces can have access control — a namespace can be configured as private (accessible only from one controller) or shared (accessible from multiple controllers). AETHER uses private namespaces to ensure each guest sees only its own storage.

**Namespace Management Commands.** NVMe defines admin commands for creating, deleting, attaching, and detaching namespaces. The Create Namespace command specifies the size and format of the new namespace. The Attach Namespace command associates a namespace with a controller (making it visible to that controller's host). The Detach Namespace command removes that association. AETHER uses these commands during initialization to configure the namespace topology.

**NVMe SR-IOV.** Like GPU SR-IOV, NVMe SR-IOV creates Virtual Functions that appear as separate NVMe controllers. Each VF can have namespaces attached to it independently. AETHER assigns VF 0 to Windows (with the Windows namespace attached) and VF 1 to Android (with the Android namespace attached). Each guest's NVMe driver sees only the namespaces attached to its VF.

**Namespace Metadata And Formatting.** When AETHER creates the Android namespace, it must format it with an Android-compatible block size (typically 4096 bytes) and leave it uninitialized. The Android bootloader and recovery system handle the initial filesystem creation. AETHER does not pre-format the Android filesystem — that would be equivalent to the manufacturer's factory flash process and is the Android image build system's responsibility.

**Performance Isolation.** SR-IOV provides memory isolation but not necessarily performance isolation. A write-heavy Android workload could saturate the SSD's write bandwidth and starve Windows. Some NVMe controllers support Quality of Service (QoS) configuration that limits bandwidth per namespace or per VF. Where available, AETHER should configure NVMe QoS to prevent cross-guest storage performance interference.

## Common AI Mistakes In This Domain

Claude generates namespace attachment code that attaches the same namespace to both VFs. This creates a race condition where both guests can write to the same storage, corrupting each other's filesystems.

Claude generates NVMe admin commands with incorrect Command Dword formats. NVMe commands have specific bit field layouts that Claude sometimes gets wrong — always verify against the spec.

Claude omits the Identify Controller command sequence that must precede namespace operations. Controllers must be identified before their capabilities (including namespace management support) can be known.

## Verification Protocol

For namespace management code:
1. Verify Create Namespace command format against NVMe spec Section 5.2
2. Verify Attach/Detach Namespace command format against NVMe spec Section 5.1
3. After setup, verify that each VF's Identify Active Namespace List contains only its intended namespace
4. Verify that accessing the Android namespace from the Windows VF returns a namespace-not-attached error

## Pre-Flight Checklist

- [ ] Download NVMe base specification from nvmexpress.org and read Chapter 8 fully
- [ ] Study `drivers/nvme/host/core.c` to understand the Linux driver's initialization sequence
- [ ] On a test NVMe SSD that supports namespace management, use `nvme-cli` to create and attach namespaces manually before implementing in AETHER
- [ ] Verify the target Snapdragon X Elite's SSD controller supports SR-IOV and namespace management
