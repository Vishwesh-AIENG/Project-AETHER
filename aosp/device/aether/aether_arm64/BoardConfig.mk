# BoardConfig.mk — board-level (hardware) configuration for AETHER.
#
# Mechanically derived from hypervisor/src/aosp_build.rs::BoardConfigMk::AETHER_DEFAULT.
# Every value here is cross-checked by AospBuildConfig::validate() in the Rust
# build-system module. Changes that break the validator break the build.
#
# Sources:
#   android.googlesource.com/platform/build/+/refs/heads/android14-release
#   source.android.com/devices/tech/ota/ab — partition size requirements
#   source.android.com/security/verifiedboot/avb — AVB configuration

# ── Architecture ──────────────────────────────────────────────────────────────
# AETHER's Android partition is ARM64-only. The 32-bit ABI is not included.
# AospBuildConfig::validate() rejects any other TARGET_ARCH.
TARGET_ARCH                 := arm64
TARGET_ARCH_VARIANT         := armv8-2a
TARGET_CPU_ABI              := arm64-v8a
# Note: AOSP 14 Soong only supports up to cortex-a76 / kryo385 for arm64.
# Snapdragon X Elite's Oryon core is Armv8.2-a class with A78-equivalent
# micro-architecture; cortex-a76 is the closest schedulable variant in this
# AOSP branch. Bump to cortex-a78 once AETHER rebases to AOSP 15+ (and update
# hypervisor/src/aosp_build.rs::BoardConfigMk::AETHER_DEFAULT.cpu_variant).
TARGET_CPU_VARIANT          := cortex-a76

# No 2nd-ABI: AETHER is 64-bit pure. Saves ~600 MiB of system image.
TARGET_2ND_ARCH             :=
TARGET_2ND_ARCH_VARIANT     :=
TARGET_2ND_CPU_ABI          :=
TARGET_2ND_CPU_VARIANT      :=

# TARGET_USES_64_BIT_BINDER is deprecated in AOSP 14+ (all devices use
# 64-bit binder by default). Kept here as a comment for reference.
# TARGET_USES_64_BIT_BINDER   := true

# ── Board platform identifier ─────────────────────────────────────────────────
# Surfaced as ro.board.platform; used by the HAL loader to pick aether_sdx libs.
# Matches BoardConfigMk::AETHER_DEFAULT.board_platform.
TARGET_BOARD_PLATFORM       := aether_sdx
TARGET_NO_BOOTLOADER        := true
TARGET_NO_KERNEL            := false
TARGET_NO_RADIOIMAGE        := true

# ── Bootloader / kernel ───────────────────────────────────────────────────────
# AETHER's own GKI defconfig (ch44 kernel_defconfig.rs) is not yet built as a
# binary. Per the project briefing — "Don't try to build the AETHER GKI kernel
# until a generic GKI Image gets you to the dispatch loop. Premature
# optimization." The kernel binary is installed via PRODUCT_COPY_FILES in
# device.mk (AOSP 14 dropped TARGET_PREBUILT_KERNEL; the build system now
# requires the kernel to land at $(PRODUCT_OUT)/kernel via PRODUCT_COPY_FILES).

BOARD_KERNEL_CMDLINE        := \
    androidboot.hardware=aether \
    androidboot.selinux=enforcing \
    androidboot.veritymode=enforcing \
    loop.max_part=7

BOARD_BOOT_HEADER_VERSION   := 4
BOARD_KERNEL_BASE           := 0x40000000
BOARD_KERNEL_PAGESIZE       := 4096
BOARD_RAMDISK_OFFSET        := 0x01000000
BOARD_KERNEL_TAGS_OFFSET    := 0x00000100

# vendor_boot.img header version. AOSP boot.img picks this up automatically
# from BOARD_BOOT_HEADER_VERSION via INTERNAL_MKBOOTIMG_VERSION_ARGS, but the
# vendor_boot.img rule (build/make/core/Makefile:1672) only consumes
# BOARD_MKBOOTIMG_ARGS — so we must pass --header_version here explicitly,
# otherwise mkbootimg fails with:
#   ValueError: --vendor_boot not compatible with given header version
BOARD_MKBOOTIMG_ARGS        := --header_version $(BOARD_BOOT_HEADER_VERSION)

# ── Partition sizes (bytes) ───────────────────────────────────────────────────
# Mirrors BoardPartitionSizes::AETHER_DEFAULT exactly. Hypervisor-side validator
# checks each non-zero and ≤ 16 TiB.
BOARD_BOOTIMAGE_PARTITION_SIZE      := 67108864          # 64 MiB
BOARD_SYSTEMIMAGE_PARTITION_SIZE    := 3221225472        # 3 GiB
BOARD_VENDORIMAGE_PARTITION_SIZE    := 1073741824        # 1 GiB
BOARD_PRODUCTIMAGE_PARTITION_SIZE   := 536870912         # 512 MiB
BOARD_DTBOIMG_PARTITION_SIZE        := 8388608           # 8 MiB
BOARD_VBMETAIMAGE_PARTITION_SIZE    := 65536             # 64 KiB (AVB requirement)
BOARD_USERDATAIMAGE_PARTITION_SIZE  := 120259084288      # 112 GiB

# Filesystem types per partition.
TARGET_USERIMAGES_USE_EXT4          := true
BOARD_SYSTEMIMAGE_FILE_SYSTEM_TYPE  := ext4
BOARD_VENDORIMAGE_FILE_SYSTEM_TYPE  := ext4
BOARD_PRODUCTIMAGE_FILE_SYSTEM_TYPE := ext4
BOARD_USERDATAIMAGE_FILE_SYSTEM_TYPE := f2fs
BOARD_FLASH_BLOCK_SIZE              := 131072

# ── Dynamic partitions (super) ────────────────────────────────────────────────
# AETHER uses dynamic partitions: system / vendor / product all live inside a
# single `super` partition that can be resized at OTA time.
# Mirrors BoardConfigMk::AETHER_DEFAULT.dynamic_partitions = true.
BOARD_USES_DYNAMIC_PARTITIONS               := true
BOARD_SUPER_PARTITION_SIZE                  := 5368709120  # 5 GiB
BOARD_SUPER_PARTITION_GROUPS                := aether_dynamic_partitions
BOARD_AETHER_DYNAMIC_PARTITIONS_PARTITION_LIST := system vendor product
BOARD_AETHER_DYNAMIC_PARTITIONS_SIZE        := 5368709120

# ── A/B slot configuration ────────────────────────────────────────────────────
# Mirrors ch19 BootControlBlock A/B layout.
AB_OTA_UPDATER  := true
AB_OTA_PARTITIONS := \
    boot \
    system \
    vendor \
    product \
    vbmeta \
    dtbo
BOARD_USES_AB_IMAGE := true

# ── AVB (Android Verified Boot 2) ─────────────────────────────────────────────
# Required: BoardConfigMk::AETHER_DEFAULT.avb_enabled = true.
# AVB key: test keys for development; PRODUCTION builds must replace these.
BOARD_AVB_ENABLE                        := true
BOARD_AVB_ALGORITHM                     := SHA256_RSA4096
BOARD_AVB_KEY_PATH                      := external/avb/test/data/testkey_rsa4096.pem
BOARD_AVB_ROLLBACK_INDEX                := 0
BOARD_AVB_MAKE_VBMETA_IMAGE_ARGS        += --flags 0
BOARD_AVB_VBMETA_SYSTEM                          := system product
BOARD_AVB_VBMETA_SYSTEM_KEY_PATH                 := external/avb/test/data/testkey_rsa4096.pem
BOARD_AVB_VBMETA_SYSTEM_ALGORITHM                := SHA256_RSA4096
BOARD_AVB_VBMETA_SYSTEM_ROLLBACK_INDEX           := 0
# Chained-partition slot index. AVB descriptors are stored in vbmeta_system
# at this slot to verify the system+product chain; index 0 is the main
# vbmeta, so chained slots start at 1.
BOARD_AVB_VBMETA_SYSTEM_ROLLBACK_INDEX_LOCATION  := 1

BOARD_AVB_VBMETA_VENDOR                          := vendor
BOARD_AVB_VBMETA_VENDOR_KEY_PATH                 := external/avb/test/data/testkey_rsa4096.pem
BOARD_AVB_VBMETA_VENDOR_ALGORITHM                := SHA256_RSA4096
BOARD_AVB_VBMETA_VENDOR_ROLLBACK_INDEX           := 0
BOARD_AVB_VBMETA_VENDOR_ROLLBACK_INDEX_LOCATION  := 2

# ── SELinux ───────────────────────────────────────────────────────────────────
# Required: BoardConfigMk::AETHER_DEFAULT.selinux_policy = Enforcing.
# Hardware Authenticity (CLAUDE.md): SELinux always enforcing in production.
BOARD_SEPOLICY_DIRS += device/aether/aether_arm64/sepolicy

# ── VINTF device manifest ─────────────────────────────────────────────────────
# AOSP 14 requires the vendor VINTF manifest to be declared here, NOT copied
# via PRODUCT_COPY_FILES (which now errors out at Kati time:
#   "VINTF metadata found in PRODUCT_COPY_FILES … use DEVICE_MANIFEST_FILE")
# The build system handles the install to vendor/etc/vintf/manifest.xml.
DEVICE_MANIFEST_FILE := device/aether/aether_arm64/manifest.xml

# ── Treble VNDK ───────────────────────────────────────────────────────────────
# AETHER's vendor partition is separate from system (ch21 PartitionLayout).
BOARD_VNDK_VERSION                  := current
PRODUCT_FULL_TREBLE_OVERRIDE        := true
PRODUCT_USE_VNDK_OVERRIDE           := true
PRODUCT_TARGET_VNDK_VERSION         := 34

# ── Vendor / system property partition split ──────────────────────────────────
BOARD_USES_VENDORIMAGE              := true
TARGET_COPY_OUT_VENDOR              := vendor
BOARD_USES_PRODUCTIMAGE             := true
TARGET_COPY_OUT_PRODUCT             := product
BOARD_USES_METADATA_PARTITION       := true

# ── GPU / display ─────────────────────────────────────────────────────────────
# Adreno is the GPU on ARM Tier (Snapdragon X Elite). The GPU SR-IOV ch39 wires
# the VF assignment; Mesa freedreno or Qualcomm proprietary libs are pulled in
# via device.mk PRODUCT_PACKAGES.
BOARD_GPU_DRIVERS                   := freedreno
TARGET_USES_GRALLOC4                := true
TARGET_USES_HWC2                    := true
BOARD_USES_DRM_HWCOMPOSER           := true
USE_OPENGL_RENDERER                 := true

# ── Network ───────────────────────────────────────────────────────────────────
BOARD_WLAN_DEVICE                   := emulator
WPA_SUPPLICANT_VERSION              := VER_0_8_X
BOARD_WPA_SUPPLICANT_DRIVER         := NL80211

# ── fstab ─────────────────────────────────────────────────────────────────────
PRODUCT_COPY_FILES += \
    device/aether/aether_arm64/fstab.aether:$(TARGET_COPY_OUT_RAMDISK)/fstab.aether \
    device/aether/aether_arm64/fstab.aether:$(TARGET_COPY_OUT_VENDOR)/etc/fstab.aether

# ── Recovery ──────────────────────────────────────────────────────────────────
# Recovery is a separate partition; configured here for completeness.
TARGET_NO_RECOVERY                  := false
BOARD_USES_RECOVERY_AS_BOOT         := false
TARGET_RECOVERY_PIXEL_FORMAT        := RGB_565
