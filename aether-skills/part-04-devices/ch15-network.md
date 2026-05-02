# SKILL.md — Chapter 15: Network Partitioning

## Confidence Disclosure

**MEDIUM for SR-IOV NIC concepts, LOW for Qualcomm WiFi adapter specifics.** WiFi SR-IOV is less standardized than GPU or NIC SR-IOV, and Qualcomm's specific implementation on Snapdragon X Elite requires vendor documentation. The fallback paravirtualized path is well-trodden territory.

## Required Primary Sources

**PCI Express Base Specification, Chapter 6** — SR-IOV, same as Chapter 13 reference.

**IEEE 802.11 Standard** — WiFi standard. Not required for basic implementation, but relevant for understanding MAC address management and BSS identification when the WiFi adapter is split between guests.

**Linux mac80211 documentation** at `Documentation/networking/mac80211-injection.rst` — Framework for WiFi driver development.

## Secondary Sources

**Linux ath11k driver** at `drivers/net/wireless/ath/ath11k/` — Qualcomm WiFi driver (for earlier Snapdragon). The Snapdragon X Elite uses ath12k, which is the successor.

**Linux ath12k driver** at `drivers/net/wireless/ath/ath12k/` — Snapdragon X Elite WiFi driver. Study its initialization and power management sequences.

**Linux e1000e driver** at `drivers/net/ethernet/intel/e1000e/` — Well-documented Intel NIC driver, useful as a reference for NIC driver patterns even though not the target hardware.

**virtio-net specification** at `docs.oasis-open.org` — The paravirtualized network device spec. Useful if AETHER needs to fall back to paravirtualized networking for the WiFi sharing case.

## Critical Concepts

**WiFi SR-IOV Is Not Standard.** Unlike Ethernet NICs where SR-IOV is well-defined and widely supported, WiFi SR-IOV is vendor-specific. The IEEE 802.11 standard does not define SR-IOV. What exists instead is a concept called "Virtual Interfaces" (VIFs) within a single WiFi driver, where one physical radio presents multiple software-defined interfaces (e.g., one in AP mode, one in station mode). Whether the Snapdragon X Elite's WiFi adapter can genuinely expose separate VFs for independent guest assignment depends on firmware and driver support that must be verified on actual hardware.

**The Practical Fallback: Dedicated Partition.** If WiFi SR-IOV is unavailable, the cleanest solution is: Android gets the WiFi adapter exclusively (since Android is the primary guest for most networking use cases), and Windows gets network access through a USB-attached Ethernet adapter or through a USB WiFi dongle assigned to the Windows controller. This avoids paravirtualization entirely and maintains the passthrough purity principle. Alternatively, AETHER provides a simple packet bridge where Windows's assigned virtual NIC tunnels through Android's WiFi — explicitly a paravirtualized path that is labeled as such in the codebase.

**MAC Address Assignment.** Each guest's network interface must have a unique MAC address. For passed-through adapters, the hardware MAC address is used. For paravirtualized interfaces, AETHER generates locally administered MAC addresses (bit 1 of the first octet set to 1) that are unique within the system. The Android partition's MAC address should ideally match a real phone's OUI prefix from the Qualcomm or phone manufacturer's registered range, for fingerprint purity.

**TCP Offload And Checksum Offload.** Modern NICs perform TCP segmentation and checksum computation in hardware. Passed-through NICs expose these capabilities directly to the guest's network driver, which enables them for performance. Paravirtualized NICs may or may not expose offload capabilities depending on the implementation. The guest's network stack must be correctly configured to match the capabilities of the NIC it receives — enabling offloads that the NIC doesn't support produces corrupted packets.

## Common AI Mistakes In This Domain

Claude conflates WiFi station mode interfaces with SR-IOV virtual functions. They are not the same — a station-mode VIF still shares the physical radio's time slots and cannot be independently partitioned in the security sense that SR-IOV provides.

Claude generates MAC address assignment code that uses the same MAC for both guests, producing an address conflict that causes both guests' networking to malfunction.

Claude omits NIC reset between guest assignments, potentially leaving TCP offload state from one guest visible to another.

## Verification Protocol

For network passthrough:
1. Verify on real hardware that the WiFi adapter supports the required number of VFs before designing around SR-IOV
2. Verify MAC address uniqueness across all guest interfaces
3. Verify TCP offload capabilities are correctly reported to each guest through the SMMU stream table

For the paravirtualized fallback:
1. Verify packet routing is strictly one-directional between guests (Android → Windows forwarding only, not Windows → Android arbitrary forwarding)
2. Verify that Android's raw WiFi traffic is not visible to Windows through the bridge

## Pre-Flight Checklist

- [ ] Test the Snapdragon X Elite WiFi adapter for SR-IOV support: `lspci -vvv | grep -A 20 "Wireless"` — look for SR-IOV Capability
- [ ] Study `drivers/net/wireless/ath/ath12k/` for the Snapdragon WiFi driver
- [ ] Test the fallback: pass the WiFi adapter to an Android guest in QEMU/KVM on Linux and verify it works before implementing in AETHER
- [ ] Decide the networking architecture (SR-IOV vs. dedicated partition) based on hardware capability before writing any code
