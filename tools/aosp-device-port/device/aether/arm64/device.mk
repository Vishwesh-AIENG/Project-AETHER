# device.mk — AETHER PRODUCT_PACKAGES, PRODUCT_COPY_FILES, PRODUCT_PROPERTY_OVERRIDES.
#
# Mirrors hypervisor/src/aosp_build.rs:
#   - AETHER_PRODUCT_PACKAGES         (21 entries)
#   - AETHER_COPY_FILES               (7 entries)
#   - AETHER_PROPERTY_OVERRIDES       (25 entries)
# Mirrors hypervisor/src/adreno_render.rs::ADRENO_PRODUCT_PACKAGES (8 entries)
#
# Run-time gate: AospBuildGate (hypervisor/src/aosp_build.rs) checks that
# every REQUIRED_PACKAGE_NAMES entry is in PRODUCT_PACKAGES.

# ── Core Android apps ───────────────────────────────────────────────────────
PRODUCT_PACKAGES += \
    Settings \
    Contacts \
    Dialer \
    Launcher3 \
    SystemUI \
    messaging \
    Camera2 \
    Gallery2

# ── microG GMS replacement ──────────────────────────────────────────────────
PRODUCT_PACKAGES += \
    GmsCore \
    FakeStore \
    GsfProxy \
    UnifiedNlp

# ── AETHER virtual HAL services ─────────────────────────────────────────────
PRODUCT_PACKAGES += \
    aether.sensors@2.1-service \
    aether.radio@2.0-service \
    aether.camera@2.7-service \
    aether.power@5-service \
    aether.health@2.1-service \
    gralloc.aether

# ── Adreno GPU userspace (ADRENO_PRODUCT_PACKAGES + AETHER_PRODUCT_PACKAGES) ─
PRODUCT_PACKAGES += \
    libEGL_adreno \
    libGLESv2_adreno \
    vulkan.adreno \
    libEGL_mesa \
    libGLESv1_CM_mesa \
    libGLESv2_mesa \
    vulkan.freedreno \
    libvulkan_freedreno \
    android.hardware.graphics.allocator-V2-service \
    android.hardware.graphics.mapper@4.0-impl \
    android.hardware.graphics.composer@2.4-service

# ── DRM (ClearKey only — no Widevine) ───────────────────────────────────────
PRODUCT_PACKAGES += \
    android.hardware.drm@1.4-service.clearkey

# ── PRODUCT_COPY_FILES (AETHER_COPY_FILES) ──────────────────────────────────
PRODUCT_COPY_FILES += \
    device/aether/arm64/configs/audio_policy_configuration.xml:system/etc/audio_policy_configuration.xml \
    device/aether/arm64/configs/media_codecs.xml:system/etc/media_codecs.xml \
    device/aether/arm64/configs/media_profiles.xml:system/etc/media_profiles.xml \
    device/aether/arm64/configs/handheld_core_hardware.xml:system/etc/permissions/handheld_core_hardware.xml \
    device/aether/arm64/configs/network_security_config.xml:res/xml/network_security_config.xml \
    device/aether/arm64/fstab.aether:$(TARGET_COPY_OUT_RAMDISK)/fstab.aether \
    device/aether/arm64/manifest.xml:vendor/etc/vintf/manifest.xml \
    device/aether/arm64/init.aether.rc:$(TARGET_COPY_OUT_VENDOR)/etc/init/init.aether.rc \
    device/aether/arm64/ueventd.aether.rc:$(TARGET_COPY_OUT_VENDOR)/etc/ueventd.rc

# ── PRODUCT_PROPERTY_OVERRIDES (AETHER_PROPERTY_OVERRIDES) ──────────────────
# ro.build.type=user is non-negotiable. UserspaceBootGate.build_type_user
# fails the boot if anything else is detected.
PRODUCT_PROPERTY_OVERRIDES += \
    ro.build.type=user \
    ro.build.tags=release-keys \
    ro.adb.secure=1 \
    ro.secure=1 \
    ro.debuggable=0 \
    ro.boot.selinux=enforcing \
    ro.product.name=aether_x1 \
    ro.product.device=aether_x1 \
    ro.product.brand=AETHER \
    ro.product.manufacturer=AETHER \
    ro.product.model=AETHER\ X1 \
    ro.hardware=aether \
    ro.board.platform=aether_sdx \
    ro.product.cpu.abi=arm64-v8a \
    ro.product.cpu.abilist=arm64-v8a \
    ro.product.cpu.abilist64=arm64-v8a \
    ro.product.cpu.abilist32= \
    ro.ram_size=8192 \
    ro.boot.verifiedbootstate=green \
    ro.boot.flash.locked=1 \
    ro.boot.veritymode=enforcing \
    ro.opengles.version=196610 \
    ro.hardware.egl=adreno \
    sys.microg.signature_spoofing=1
