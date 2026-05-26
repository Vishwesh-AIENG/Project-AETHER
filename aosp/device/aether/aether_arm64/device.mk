# device.mk — product-level package, copy, and property declarations for AETHER.
#
# Mechanically derived from hypervisor/src/aosp_build.rs:
#   - AETHER_PRODUCT_PACKAGES       → PRODUCT_PACKAGES
#   - AETHER_COPY_FILES             → PRODUCT_COPY_FILES
#   - AETHER_PROPERTY_OVERRIDES     → PRODUCT_PROPERTY_OVERRIDES
#
# Validation: every PRODUCT_PACKAGES entry must be backed by an actual Android.bp
# module or an AOSP-shipped APK. The AOSP build will hard-fail with "Could not
# find required modules" if the module isn't resolvable; see Android.bp in this
# directory for AETHER's contributions.

# ── Soong namespaces ──────────────────────────────────────────────────────────
# external/mesa3d/Android.mk requires that any product setting BOARD_GPU_DRIVERS
# (we set it to `freedreno` in BoardConfig.mk) declares external/mesa3d in
# PRODUCT_SOONG_NAMESPACES so its modules resolve from the right namespace.
# Without this, Kati fails with:
#   external/mesa3d/Android.mk:13: error: must be in PRODUCT_SOONG_NAMESPACES
PRODUCT_SOONG_NAMESPACES += external/mesa3d

# ── PRODUCT_PACKAGES ──────────────────────────────────────────────────────────

# Core Android apps. Sourced from AOSP base inheritances in aether_arm64.mk
# but listed explicitly here so device.mk has the full picture in one place
# (AOSP build will deduplicate).
PRODUCT_PACKAGES += \
    Settings \
    Contacts \
    Dialer \
    Launcher3 \
    SystemUI \
    messaging \
    Camera2 \
    Gallery2

# microG GMS replacement (ch22). These four packages must be present in the
# AOSP source tree under vendor/microg/ — see README.md in this directory for
# the procedure to drop them in.
#
# GmsCore     — replaces com.google.android.gms (FCM / FusedLocation / Auth)
# FakeStore   — replaces com.android.vending (Play Store package name stub)
# GsfProxy    — Google Services Framework shim
# UnifiedNlp  — network location provider backend
PRODUCT_PACKAGES += \
    GmsCore \
    FakeStore \
    GsfProxy \
    UnifiedNlp

# AETHER virtual HAL services. All declared in Android.bp.
PRODUCT_PACKAGES += \
    aether.sensors@2.1-service \
    aether.radio@2.0-service \
    aether.camera@2.7-service \
    aether.power@5-service \
    aether.health@2.1-service

# Adreno GPU userspace + Gralloc allocator. The "_adreno" / "vulkan.adreno"
# names match the proprietary Qualcomm driver pull-ins; substitute "_freedreno"
# variants here if building with Mesa (ch46 default).
PRODUCT_PACKAGES += \
    libEGL_adreno \
    libGLESv2_adreno \
    vulkan.adreno \
    gralloc.aether

# ClearKey DRM (Widevine L3 fallback per ch49 compat strategy).
PRODUCT_PACKAGES += \
    android.hardware.drm@1.4-service.clearkey

# ── PRODUCT_COPY_FILES ────────────────────────────────────────────────────────
# Each entry copies a file from the source tree into the built image at the
# given partition-relative destination.
#
# All sources under device/aether/aether_arm64/configs/ are minimum stubs in
# this initial drop — see README.md in this directory.

PRODUCT_COPY_FILES += \
    device/aether/aether_arm64/configs/audio_policy_configuration.xml:system/etc/audio_policy_configuration.xml \
    device/aether/aether_arm64/configs/media_codecs.xml:system/etc/media_codecs.xml \
    device/aether/aether_arm64/configs/media_profiles.xml:system/etc/media_profiles.xml \
    device/aether/aether_arm64/configs/handheld_core_hardware.xml:system/etc/permissions/handheld_core_hardware.xml \
    device/aether/aether_arm64/configs/network_security_config.xml:res/xml/network_security_config.xml \
    device/aether/aether_arm64/manifest.xml:vendor/etc/vintf/manifest.xml

# fstab is copied by BoardConfig.mk to both ramdisk and vendor/etc paths.

# ── PRODUCT_PROPERTY_OVERRIDES ────────────────────────────────────────────────
# Written to vendor/build.prop. Surfaced as ro.* / sys.* system properties at
# runtime. Hardware Authenticity (CLAUDE.md §Hardware Authenticity):
#   - ro.build.type must be "user" — never "userdebug"
#   - ADB disabled (ro.adb.secure=1, ro.secure=1, ro.debuggable=0)
#   - SELinux enforcing
#   - RAM size a round phone-class value
#   - CPU ABI list is 64-bit-only

PRODUCT_PROPERTY_OVERRIDES += \
    ro.build.type=user \
    ro.build.tags=release-keys \
    ro.adb.secure=1 \
    ro.secure=1 \
    ro.debuggable=0 \
    ro.boot.selinux=enforcing

PRODUCT_PROPERTY_OVERRIDES += \
    ro.product.name=aether_x1 \
    ro.product.device=aether_x1 \
    ro.product.brand=AETHER \
    ro.product.manufacturer=AETHER \
    ro.product.model="AETHER X1" \
    ro.hardware=aether \
    ro.board.platform=aether_sdx

PRODUCT_PROPERTY_OVERRIDES += \
    ro.product.cpu.abi=arm64-v8a \
    ro.product.cpu.abilist=arm64-v8a \
    ro.product.cpu.abilist64=arm64-v8a \
    ro.product.cpu.abilist32=

# 8 GiB RAM — valid round phone-class value per CLAUDE.md (4/6/8/12/16).
PRODUCT_PROPERTY_OVERRIDES += \
    ro.ram_size=8192

# AVB verified-boot state (set by AVB at runtime; declared here for completeness).
PRODUCT_PROPERTY_OVERRIDES += \
    ro.boot.verifiedbootstate=green \
    ro.boot.flash.locked=1 \
    ro.boot.veritymode=enforcing

# GLES version: Adreno 740 supports OpenGL ES 3.2 (high-word=3, low-word=2 →
# (3 << 16) | 2 = 196610).
PRODUCT_PROPERTY_OVERRIDES += \
    ro.opengles.version=196610 \
    ro.hardware.egl=adreno

# microG: enable signature spoofing at the system level. Requires the
# frameworks/base patch — see vendor/microg/README in the upstream microG repo.
PRODUCT_PROPERTY_OVERRIDES += \
    sys.microg.signature_spoofing=1

# ── Build variant invariant ───────────────────────────────────────────────────
# AETHER ships only the `user` variant. AospBuildConfig::validate() rejects
# anything else. This is enforced at the lunch combo level (only -user is
# registered in AndroidProducts.mk), but assert it here too.
ifeq ($(TARGET_BUILD_VARIANT),userdebug)
    $(error AETHER does not support the userdebug variant. Use aether_arm64-user.)
endif
ifeq ($(TARGET_BUILD_VARIANT),eng)
    $(error AETHER does not support the eng variant. Use aether_arm64-user.)
endif
