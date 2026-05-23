# BoardConfig.mk — AETHER board-level configuration.
#
# Mirrors hypervisor/src/aosp_build.rs::BoardConfigMk::AETHER_DEFAULT
# Mirrors hypervisor/src/aosp_build.rs::BoardPartitionSizes::AETHER_DEFAULT
# Mirrors hypervisor/src/adreno_render.rs::ADRENO_AOSP_BUILD_VARS

# ── Target architecture ─────────────────────────────────────────────────────
TARGET_ARCH                := arm64
TARGET_ARCH_VARIANT        := armv8-2a
TARGET_CPU_ABI             := arm64-v8a
TARGET_CPU_VARIANT         := cortex-a510
TARGET_BOARD_PLATFORM      := aether_sdx

# 64-bit only; no 32-bit ABI lists.
TARGET_2ND_ARCH            :=
TARGET_2ND_ARCH_VARIANT    :=
TARGET_2ND_CPU_ABI         :=
TARGET_2ND_CPU_VARIANT     :=

# ── Kernel ─────────────────────────────────────────────────────────────────
TARGET_NO_BOOTLOADER       := true
TARGET_NO_KERNEL           := false
BOARD_KERNEL_BASE          := 0x40000000
BOARD_KERNEL_PAGESIZE      := 4096
BOARD_KERNEL_CMDLINE       := \
    earlyprintk console=ttyAMA0,115200 \
    androidboot.hardware=aether androidboot.selinux=enforcing \
    androidboot.verifiedbootstate=green
BOARD_BOOT_HEADER_VERSION  := 4
BOARD_MKBOOTIMG_ARGS       := --header_version $(BOARD_BOOT_HEADER_VERSION)

# ── Partition sizes (BoardPartitionSizes::AETHER_DEFAULT) ───────────────────
# boot=64 MiB, system=3 GiB, vendor=1 GiB, product=512 MiB,
# dtbo=8 MiB, vbmeta=64 KiB (AVB requirement), userdata=112 GiB.
BOARD_BOOTIMAGE_PARTITION_SIZE      := 67108864
BOARD_SYSTEMIMAGE_PARTITION_SIZE    := 3221225472
BOARD_VENDORIMAGE_PARTITION_SIZE    := 1073741824
BOARD_PRODUCTIMAGE_PARTITION_SIZE   := 536870912
BOARD_DTBOIMG_PARTITION_SIZE        := 8388608
BOARD_VBMETAIMAGE_PARTITION_SIZE    := 65536
BOARD_USERDATAIMAGE_PARTITION_SIZE  := 120259084288

# ── Filesystems ─────────────────────────────────────────────────────────────
BOARD_SYSTEMIMAGE_FILE_SYSTEM_TYPE   := ext4
BOARD_VENDORIMAGE_FILE_SYSTEM_TYPE   := ext4
BOARD_PRODUCTIMAGE_FILE_SYSTEM_TYPE  := ext4
BOARD_USERDATAIMAGE_FILE_SYSTEM_TYPE := f2fs

# ── Dynamic partitions (super) ──────────────────────────────────────────────
PRODUCT_USE_DYNAMIC_PARTITIONS    := true
BOARD_SUPER_PARTITION_SIZE        := 4831838208
BOARD_SUPER_PARTITION_GROUPS      := aether_dynamic_partitions
BOARD_AETHER_DYNAMIC_PARTITIONS_PARTITION_LIST := system vendor product
BOARD_AETHER_DYNAMIC_PARTITIONS_SIZE           := 4831838208

# ── A/B slotting ────────────────────────────────────────────────────────────
AB_OTA_UPDATER       := true
AB_OTA_PARTITIONS    := boot system vendor product vbmeta dtbo

# ── AVB (Android Verified Boot 2) ───────────────────────────────────────────
BOARD_AVB_ENABLE              := true
BOARD_AVB_ALGORITHM           := SHA256_RSA4096
BOARD_AVB_ROLLBACK_INDEX      := 0
BOARD_AVB_KEY_PATH            := external/avb/test/data/testkey_rsa4096.pem
BOARD_AVB_BOOT_KEY_PATH       := external/avb/test/data/testkey_rsa4096.pem
BOARD_AVB_BOOT_ROLLBACK_INDEX := 0
BOARD_AVB_VBMETA_SYSTEM       := system
BOARD_AVB_VBMETA_VENDOR       := vendor

# ── SELinux ─────────────────────────────────────────────────────────────────
BOARD_SEPOLICY_DIRS += device/aether/arm64/sepolicy
# Enforcing mode is set via ro.boot.selinux property; build defaults to enforcing.

# ── Adreno GPU (ADRENO_AOSP_BUILD_VARS) ─────────────────────────────────────
BOARD_GPU_DRIVERS            := adreno
BOARD_USES_DRM_HWCOMPOSER    := true
TARGET_USES_GRALLOC4         := true
TARGET_USES_HWC2             := true
BOARD_USES_OPENGL_RENDERER   := true

# ── VNDK / Treble ───────────────────────────────────────────────────────────
BOARD_VNDK_VERSION                := current
PRODUCT_FULL_TREBLE_OVERRIDE      := true
PRODUCT_OTA_ENFORCE_VINTF_KERNEL_REQUIREMENTS := true
