# SKILL.md — Chapter 20: The Linux Kernel

## Confidence Disclosure

**MEDIUM for general Linux kernel knowledge, LOW for Android Common Kernel specifics and ARM64 device tree authoring.** Claude knows Linux kernel architecture well but the Android-specific patches, the Qualcomm-specific drivers, and the device tree syntax for a novel virtual hardware platform require primary source verification.

## Required Primary Sources

**Android Common Kernel** at android.googlesource.com/kernel/common — The exact kernel AETHER builds from. Read the `README` and `BUILDING` documentation in the repository root.

**Linux kernel documentation** at `Documentation/` in the kernel source tree:

| File | Topic | Priority |
|---|---|---|
| `arm64/booting.rst` | ARM64 kernel boot protocol | MANDATORY |
| `devicetree/usage-model.rst` | Device tree fundamentals | Essential |
| `devicetree/bindings/` | Per-driver DT binding specs | Reference as needed |
| `admin-guide/kernel-parameters.txt` | Kernel command line parameters | Reference |
| `core-api/memory-hotplug.rst` | Memory layout | Read |

**Device Tree Specification** at devicetree.org/specifications — The authoritative spec for device tree syntax and semantics.

**Qualcomm upstream kernel patches** — Search `lore.kernel.org` for "Qualcomm Snapdragon" patches. These reveal what drivers and DT bindings the Snapdragon X Elite platform uses.

## Secondary Sources

**AOSP device configurations** for existing Snapdragon devices at `device/qcom/` in AOSP source — Shows how real Android device configurations are structured. AETHER's device configuration follows the same pattern.

**Android kernel configs** at `arch/arm64/configs/` in the Android Common Kernel — The base kernel configuration Google uses for Android. AETHER's kernel config starts here.

**linux-kernel mailing list archives** at lore.kernel.org — For Snapdragon X Elite specific driver development discussions.

## Critical Concepts

**ARM64 Kernel Boot Protocol.** The Linux ARM64 kernel has a specific protocol it expects from the bootloader. The kernel Image binary has a 64-byte header at offset 0 containing magic (`MZ` for PE/COFF compatibility), the load offset, image size, flags, and a text offset. The bootloader must load the kernel at a physical address that is aligned to 2MB and satisfies the load offset requirement. The DTB must be placed in memory before the kernel runs and its physical address passed in X0 at kernel entry. X1, X2, X3 must be zero. Violating any of these produces a kernel that hangs silently at the first instruction.

**The Device Tree For AETHER's Android Partition.** The device tree is the most important authoring task in this chapter. It is an XML-like binary structure that describes every piece of hardware the Android kernel will interact with. For AETHER's Android partition, the device tree must describe:
- The CPU cores assigned to Android, with correct MPIDR affinity values and capacity information
- The memory regions assigned to Android
- The GIC (interrupt controller) with the Android partition's GIC base addresses
- The ARM architectural timer with correct interrupt IDs
- The Adreno GPU VF with its BAR addresses and interrupt
- The NVMe controller VF with its BAR addresses
- The assigned USB controllers with their BAR addresses
- The virtual serial device for early console output (essential for debugging)
- The virtual sensors (accelerometer, gyroscope, magnetometer) via I2C bus simulation
- The virtual modem via virtual UART

Each device node in the device tree uses a specific binding format documented in `Documentation/devicetree/bindings/`. The binding specifies which properties are required, which are optional, and what values are valid. Using wrong property names or values produces devices the kernel silently ignores.

**Android-Specific Kernel Configuration.** The Android Common Kernel has mandatory configuration options defined in `android/configs/` within the kernel source. These cover security features (CONFIG_SECURITY_SELINUX, CONFIG_AUDIT), Android Binder IPC (CONFIG_ANDROID_BINDER_IPC), ashmem (CONFIG_ASHMEM), ION memory allocator (CONFIG_ION), and many others. Missing mandatory options causes Android userspace to fail at startup with cryptic errors. AETHER's kernel configuration must satisfy all Android mandatory config requirements plus the AETHER-specific hardware driver configs.

**GKI — Generic Kernel Image.** Android 12 and later require kernels to conform to the Generic Kernel Image standard, which defines a stable KMI (Kernel Module Interface) so that vendor modules compiled for one GKI version work across minor GKI revisions. AETHER's kernel must either conform to GKI (if building for Android 12+) or must include all needed drivers compiled in (not as modules), which avoids GKI concerns but increases kernel size.

**SELinux Policy.** Android enforces SELinux in enforcing mode. Every process, file, and device has an SELinux label, and all access is controlled by policy. AETHER's virtual devices must have appropriate SELinux labels or they will be inaccessible to Android userspace regardless of standard file permissions. The SELinux policy is part of the AOSP build, and adding new devices requires adding policy entries.

## Common AI Mistakes In This Domain

Claude generates device tree nodes with wrong `compatible` strings. The `compatible` string must exactly match a string the kernel driver registers with. A typo of any kind means the driver never binds to the device.

Claude generates device tree interrupt specifiers in the wrong format. For GICv3, interrupts are specified as a 3-cell tuple: `<type number flags>` where type is 0 for SPI or 1 for PPI, number is the interrupt number (0-based within the type's range), and flags are the trigger type (4 for level active-high). Claude sometimes produces 2-cell GICv2 format tuples instead of 3-cell GICv3 format.

Claude generates device tree memory nodes with wrong address/size cell counts. If the root node has `#address-cells = <2>` and `#size-cells = <2>`, all memory reg properties need two 32-bit cells for the address and two for the size. Claude sometimes mixes 1-cell and 2-cell formats.

Claude suggests kernel configs with mutually exclusive options enabled simultaneously (e.g., enabling both `CONFIG_CPU_FREQ_GOV_PERFORMANCE` and `CONFIG_CPU_FREQ_GOV_POWERSAVE` as built-in when only one can be the default).

## Verification Protocol

For the device tree:
1. Compile with `dtc -I dts -O dtb -W no-unit_address_vs_reg` and fix all warnings — warnings indicate binding violations
2. Boot the kernel with the DTB in QEMU and check `dmesg | grep -E "(probe|error|fail)"` — every device should show a successful probe
3. Verify each device node's compatible string against the corresponding binding in `Documentation/devicetree/bindings/`

For the kernel configuration:
1. Run `scripts/kconfig/merge_config.sh` with Android's mandatory config fragments to detect missing required options
2. Build the kernel and verify it boots to the Android init process in QEMU before testing on AETHER hardware

## Pre-Flight Checklist

- [ ] Clone Android Common Kernel: `git clone https://android.googlesource.com/kernel/common`
- [ ] Read `Documentation/arm64/booting.rst` completely
- [ ] Read the Device Tree Specification at devicetree.org
- [ ] Browse `Documentation/devicetree/bindings/` for every device type AETHER's Android partition uses
- [ ] Study an existing Qualcomm device's device tree in AOSP (e.g., `device/qcom/sm8450-common/`) as a reference
- [ ] Build a minimal Android kernel for QEMU's `virt` machine and boot Android userspace in it before starting AETHER-specific kernel work
