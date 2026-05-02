# SKILL.md — Chapter 21: AOSP And The Android Userspace

## Confidence Disclosure

**MEDIUM for AOSP build system concepts, LOW for device-specific HAL implementation, LOW for Soong build rule syntax details.** Claude understands the overall AOSP architecture well but gets specific build rule syntax, HAL interface versions, and device configuration variable names wrong frequently. The AOSP build system is large and version-sensitive — what is correct for Android 12 may be wrong for Android 14.

## Required Primary Sources

**Android documentation at source.android.com:**

| Page | Topic | Priority |
|---|---|---|
| Devices > Architecture > HALs | Hardware Abstraction Layer overview | MANDATORY |
| Devices > Architecture > HIDL | HAL Interface Definition Language | Essential |
| Devices > Architecture > AIDL for HALs | Newer AIDL-based HALs (Android 11+) | Essential |
| Setup > Build > Overview | AOSP build system overview | Read |
| Setup > Build > Building | Build commands | Read |

**Android Compatibility Definition Document (CDD)** — current version at source.android.com. This defines what any Android device must support. AETHER's Android image must satisfy the CDD for the Android version it targets.

**Soong build system documentation** at `build/soong/docs/` in AOSP source — The definitive reference for `Android.bp` file syntax.

## Secondary Sources

**Existing Qualcomm device configurations** in AOSP at `device/qcom/` — The closest existing reference to AETHER's hardware. Study `device/qcom/sm8450-common/` or similar as a template.

**Android Generic System Image (GSI)** documentation at source.android.com — GSI is a generic Android system image that runs on any Project Treble-compliant device. Understanding GSI helps understand how to separate the generic Android system from device-specific vendor code.

**Android Cuttlefish** at `device/google/cuttlefish/` in AOSP — Google's virtual Android device. This is the most direct reference for how to configure an Android image that runs on virtual hardware rather than a physical phone.

## Critical Concepts

**The AOSP Directory Structure For Device Configuration.** Every Android device has a device configuration directory at `device/<manufacturer>/<device_name>/`. This directory contains:
- `Android.mk` or `Android.bp` — build rules for device-specific code
- `BoardConfig.mk` — hardware configuration variables (architecture, partition sizes, kernel config, bootloader config)
- `device.mk` — list of packages, HAL implementations, and properties to include
- `manifest.xml` — declares which HAL interfaces the device implements (Treble manifest)

AETHER creates its own `device/aether/aether_x1/` (or similar) directory with all of these files authored for AETHER's virtual hardware.

**Android Treble And HAL Interfaces.** Android Treble is the architecture that separates the Android framework from device-specific code. HALs (Hardware Abstraction Layers) are the interface between them. Each HAL is versioned and defined in a HIDL (HAL Interface Definition Language) or AIDL file. AETHER must implement HALs for every hardware type the Android framework expects: graphics (EGL/GLES), audio, sensors, camera (even if returning "not available"), power, and others. For each HAL, AETHER either provides a real implementation (talking to the passed-through hardware via a Linux driver) or a stub implementation that returns appropriate "not available" responses.

**BoardConfig.mk Critical Variables.** The `BoardConfig.mk` file defines variables that control the entire build. The most critical for AETHER are:
- `TARGET_ARCH := arm64` — must be arm64
- `TARGET_BOARD_PLATFORM` — the SoC identifier, affects which drivers are included
- `BOARD_KERNEL_IMAGE_NAME` — the kernel binary filename
- `BOARD_BOOTIMAGE_PARTITION_SIZE` — must match the NVMe namespace partition layout
- `BOARD_SYSTEMIMAGE_PARTITION_SIZE` — must be large enough for the system partition
- `TARGET_KERNEL_CONFIG` — which kernel defconfig to use

Incorrect partition sizes in BoardConfig cause build-time or boot-time failures that are confusing to diagnose.

**The Vendor Partition And Treble Compliance.** Android Treble requires the system partition to contain only generic AOSP code, and the vendor partition to contain device-specific code (kernel modules, HAL implementations, firmware). This separation means a GSI can run on AETHER's vendor partition. AETHER's vendor partition contains: the Adreno GPU user-space driver blobs (from Freedreno or Qualcomm), the Qualcomm WiFi firmware blobs, the virtual sensor HAL implementation, and the virtual modem RIL implementation.

**Android Properties System.** Android's property system (accessed via `getprop`/`setprop`) is used by apps and the system to discover device identity. Properties like `ro.product.model`, `ro.product.manufacturer`, `ro.product.brand`, `ro.build.fingerprint` identify the device. These are set in `device.mk` and `build.prop`. AETHER sets these to match the virtual device identity — specifically, they must match the values reported by the virtual modem's AT+CGMM and AT+CGMI responses, and must match the values AETHER's virtual hardware presents through CPUID-equivalent queries.

## Common AI Mistakes In This Domain

Claude generates `Android.bp` files with incorrect syntax — particularly wrong module types (`cc_binary` vs `cc_library_shared` vs `cc_defaults`) or wrong property names within module blocks.

Claude generates `manifest.xml` entries with wrong HAL interface versions. HIDL interface versions follow a `major.minor` format and must match the version the framework expects for the targeted Android release.

Claude generates `BoardConfig.mk` with partition sizes that don't match the NVMe namespace layout, producing out-of-space errors during first boot.

Claude generates HAL implementations that claim to implement an interface but return wrong error codes that the framework interprets as fatal errors rather than "feature not available."

## Verification Protocol

For the device configuration:
1. Run `m check-vintf` to validate the Treble manifest against the framework compatibility matrix
2. Run `m` (full build) and resolve all build errors before attempting to boot
3. Boot in Android Cuttlefish (emulator) with the system partition from your build and verify all expected services start

For the build system:
1. Verify partition sizes in BoardConfig match the actual NVMe namespace sizes
2. Verify `ro.build.fingerprint` format matches Android's expected format: `brand/product/device:version/id/tags:type/keys`

## Pre-Flight Checklist

- [ ] Read all AOSP HAL architecture documentation at source.android.com
- [ ] Set up and build AOSP from source for `aosp_arm64` target to understand the build system before adding device customizations
- [ ] Study `device/google/cuttlefish/` as the primary template for AETHER's device configuration
- [ ] Understand which HALs are mandatory (must have real implementation) vs. optional (can be stubbed) for the Android CDD
- [ ] Read the Soong build system docs at `build/soong/docs/`
