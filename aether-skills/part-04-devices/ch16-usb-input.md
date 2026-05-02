# SKILL.md — Chapter 16: USB And Input Routing

## Confidence Disclosure

**LOW for xHCI controller internals, MEDIUM for USB protocol concepts, MEDIUM for the input switching mechanism concept.** USB controller passthrough at the register level requires the xHCI specification. The input switching mechanism — the one user-facing feature that crosses partition boundaries — requires careful design to ensure it cannot be exploited.

## Required Primary Sources

**eXtensible Host Controller Interface (xHCI) Specification** — available at intel.com (search "xHCI specification"). The authoritative reference for USB 3.x host controller operation.

| Section | Topic | Priority |
|---|---|---|
| Chapter 3 | USB Device Model | Read |
| Chapter 4 | Host Controller Model | Essential |
| Chapter 5 | Operational Model | Critical |
| Chapter 6 | Register Interface | Reference |

**USB 3.2 Specification** — available at usb.org. For understanding USB device classes and enumeration.

**Human Interface Device (HID) Specification** — USB HID class spec at usb.org. Defines the keyboard and mouse protocol that the integrated input device uses.

## Secondary Sources

**Linux xHCI driver** at `drivers/usb/host/xhci.c` — Reference implementation of the xHCI host controller driver.

**Linux USB HID driver** at `drivers/hid/usbhid/` — How Linux processes HID events from USB keyboards and mice.

**Linux input subsystem** at `drivers/input/` — How Linux's input subsystem routes events from HID devices to applications. Understanding this helps design the cross-partition input switching.

**VFIO USB passthrough** — `drivers/usb/host/xhci-pci.c` for how the xHCI PCI device is set up for passthrough.

## Critical Concepts

**xHCI Controller Architecture.** An xHCI (eXtensible Host Controller Interface) is the USB 3.x host controller standard. It manages all USB ports on a set of physical connectors. The controller has a register space (accessed via MMIO) that contains capability registers, operational registers, and runtime registers. The key operational concept is the Transfer Ring: a circular buffer in system memory that the controller reads to find USB transactions to execute. The driver writes Transfer Request Blocks (TRBs) to the ring, rings a doorbell register, and the controller executes the transfers asynchronously.

**Controller-Level Passthrough.** AETHER assigns entire xHCI controllers to guests, not individual USB ports. A laptop typically has multiple xHCI controllers instantiated on the PCIe bus — one for the integrated keyboard/trackpad, one for USB-A ports, one for USB-C ports, sometimes more. AETHER reads the PCIe topology to enumerate controllers and assigns each to a guest. A device plugged into a port managed by an Android-assigned controller is visible only to Android.

**The Integrated Input Device Problem.** The laptop's built-in keyboard and trackpad connect to one xHCI controller (or sometimes directly to an embedded controller via I2C/SPI, bypassing USB entirely). There is only one integrated keyboard and one trackpad. Exclusively assigning them to one guest means the other guest cannot receive keyboard input at all. AETHER's solution is a cross-partition input switching mechanism where the hypervisor itself monitors a specific key combination and reassigns the integrated input controller between guests.

**Input Switching Implementation.** AETHER intercepts all key events from the integrated keyboard while it is assigned to either guest. When it detects the switching key combination (e.g., Ctrl+Alt+Tab), it performs a live controller reassignment: disabling the controller in the current guest's SMMU configuration, resetting the controller, and re-enabling it for the other guest. This reassignment takes approximately 50–200ms and is imperceptible to the user. The key events that trigger the switch are consumed by AETHER and not delivered to either guest.

**Security Of The Switching Mechanism.** The switching mechanism is the only feature in AETHER that crosses partition boundaries, and it must be hardened against abuse. A guest must not be able to trigger a switch through software means — only the physical key combination pressed on the real keyboard can do so. AETHER's keyboard interception must happen below any guest-visible layer. The implementation monitors raw HID reports from the controller before they reach the guest's input subsystem.

**Embedded Controller (EC) Path.** On some ARM laptops, the keyboard and trackpad bypass USB entirely and connect through an Embedded Controller (EC) on an I2C or SPI bus. In this case, xHCI passthrough is irrelevant for the integrated input, and AETHER must intercept at the EC communication layer instead. This is more complex and requires understanding the specific EC protocol used by the target laptop.

## Common AI Mistakes In This Domain

Claude generates USB passthrough code that operates at the device level rather than the controller level, which is the wrong granularity — AETHER operates on entire controllers.

Claude designs the input switching mechanism as a software-triggerable event that guests can invoke via a hypercall. This would allow a malicious guest to steal input focus from the other guest programmatically.

Claude omits the xHCI controller reset step during reassignment, leaving the controller in a state where the previous guest's transfer rings are still programmed — causing the new guest's driver to encounter unexpected state.

## Verification Protocol

For USB passthrough:
1. Verify the SMMU stream table entries for the xHCI controller are in translated mode, not bypass
2. Verify controller reset is performed before reassignment
3. Verify that USB device enumeration in the guest produces correct device descriptors

For the input switching mechanism:
1. Verify that the switching key combination cannot be triggered via a guest-issued hypercall
2. Verify that key events that trigger the switch are not delivered to either guest
3. Verify that the controller state is clean after switching — the new guest's driver must enumerate the integrated keyboard as if freshly plugged in

## Pre-Flight Checklist

- [ ] Download xHCI specification from intel.com and read Chapters 4 and 5
- [ ] Identify on the target hardware which xHCI controllers exist and which USB ports they manage: `lspci | grep -i usb` then `lsusb -t`
- [ ] Determine if the integrated keyboard uses USB HID or an embedded controller I2C/SPI path — this determines which interception layer AETHER needs
- [ ] Study `drivers/usb/host/xhci.c` initialization sequence
- [ ] Prototype the input switching mechanism in QEMU before hardware implementation
